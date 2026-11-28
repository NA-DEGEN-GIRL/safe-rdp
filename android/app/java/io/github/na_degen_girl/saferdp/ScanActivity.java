package io.github.na_degen_girl.saferdp;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.OutputConfiguration;
import android.hardware.camera2.params.SessionConfiguration;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Size;
import android.view.Gravity;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;
import java.util.Arrays;
import java.util.List;

/**
 * Reads a key's QR code (as `safe-rdp key qr` shows it) with the camera and stores the key. The
 * frames are decoded natively from the camera's buffers; nothing is saved, and the screen cannot
 * be captured while the code is in view.
 *
 * Opening the camera and configuring its session complete later, on callbacks: each checks that
 * the screen is still in use (`paused`) and the camera still wanted, and closes what came too late.
 */
public final class ScanActivity extends Activity implements SurfaceHolder.Callback {
    private SurfaceView preview;
    private TextView hint;
    private HandlerThread thread;
    private Handler background;
    private CameraDevice camera;
    private CameraCaptureSession capture;
    private ImageReader reader;
    private volatile boolean done;
    private boolean paused = true;
    /** openCamera was called and has not answered yet. */
    private boolean opening;
    /** Counts camera openings: a callback from an earlier one (the screen left and came back
     *  meanwhile) is told apart from the current one's. */
    private int openGen;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Native.load();
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.BLACK);
        preview = new SurfaceView(this);
        preview.setSecure(true);
        preview.getHolder().addCallback(this);
        root.addView(preview, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT, Gravity.CENTER));
        hint = Ui.text(this, getString(R.string.scan_hint), 16);
        hint.setTextColor(Color.WHITE);
        hint.setBackgroundColor(0x80000000);
        hint.setGravity(Gravity.CENTER);
        root.addView(hint, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM));
        int pad = Ui.dp(this, 16);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets i = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            hint.setPadding(pad + i.left, pad, pad + i.right, pad + i.bottom);
            return insets;
        });
        setContentView(root);
    }

    @Override
    protected void onResume() {
        super.onResume();
        paused = false;
        thread = new HandlerThread("qr");
        thread.start();
        background = new Handler(thread.getLooper());
        if (preview.getHolder().getSurface().isValid()) open();
    }

    @Override
    protected void onPause() {
        paused = true;
        opening = false;
        openGen++;
        closeCamera();
        if (thread != null) thread.quitSafely();
        thread = null;
        background = null;
        super.onPause();
    }

    @Override
    public void surfaceCreated(SurfaceHolder h) {
        if (thread != null) open();
    }

    @Override
    public void surfaceChanged(SurfaceHolder h, int format, int w, int ht) {}

    @Override
    public void surfaceDestroyed(SurfaceHolder h) {
        closeCamera();
    }

    private void open() {
        if (paused || opening || camera != null || done) return;
        CameraManager cm = getSystemService(CameraManager.class);
        try {
            String id = null;
            for (String c : cm.getCameraIdList()) {
                Integer facing = cm.getCameraCharacteristics(c).get(CameraCharacteristics.LENS_FACING);
                if (id == null || (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK)) id = c;
            }
            if (id == null) {
                fail(getString(R.string.no_camera));
                return;
            }
            StreamConfigurationMap map = cm.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            Size[] sizes = map == null ? null : map.getOutputSizes(ImageFormat.YUV_420_888);
            if (sizes == null || sizes.length == 0) {
                fail(getString(R.string.camera_failed, -2));
                return;
            }
            Size size = pick(sizes);
            if (reader == null) {
                reader = ImageReader.newInstance(size.getWidth(), size.getHeight(), ImageFormat.YUV_420_888, 2);
                reader.setOnImageAvailableListener(this::onFrame, background);
            }
            opening = true;
            final int gen = ++openGen;
            cm.openCamera(id, getMainExecutor(), new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice d) {
                    if (gen != openGen) {
                        d.close();
                        return;
                    }
                    opening = false;
                    if (paused || done || reader == null || background == null || !preview.getHolder().getSurface().isValid()) {
                        d.close();
                        return;
                    }
                    camera = d;
                    start();
                }

                @Override
                public void onDisconnected(CameraDevice d) {
                    if (gen == openGen) opening = false;
                    d.close();
                    if (camera == d) camera = null;
                }

                @Override
                public void onError(CameraDevice d, int error) {
                    d.close();
                    if (camera == d) camera = null;
                    if (gen != openGen) return;
                    opening = false;
                    fail(getString(R.string.camera_failed, error));
                }
            });
            // After the camera has a request in flight: the size change recreates the surface, and
            // `open` from that is then a no-op.
            preview.getHolder().setFixedSize(size.getWidth(), size.getHeight());
        } catch (CameraAccessException | SecurityException | IllegalArgumentException e) {
            opening = false;
            fail(Ui.why(e));
        }
    }

    /** About 1280x720: enough pixels per module for a version 5 code at arm's length, little work. */
    private static Size pick(Size[] sizes) {
        Size best = sizes[0];
        for (Size s : sizes) {
            long d = Math.abs((long) s.getWidth() * s.getHeight() - 1280L * 720);
            long b = Math.abs((long) best.getWidth() * best.getHeight() - 1280L * 720);
            if (d < b) best = s;
        }
        return best;
    }

    private void start() {
        CameraDevice cam = camera;
        ImageReader r = reader;
        if (cam == null || r == null || !preview.getHolder().getSurface().isValid()) return;
        try {
            List<OutputConfiguration> outs = Arrays.asList(new OutputConfiguration(preview.getHolder().getSurface()), new OutputConfiguration(r.getSurface()));
            cam.createCaptureSession(new SessionConfiguration(SessionConfiguration.SESSION_REGULAR, outs, getMainExecutor(), new CameraCaptureSession.StateCallback() {
                @Override
                public void onConfigured(CameraCaptureSession s) {
                    if (paused || done || camera != cam || reader != r || background == null) {
                        s.close();
                        return;
                    }
                    capture = s;
                    try {
                        CaptureRequest.Builder b = cam.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
                        b.addTarget(preview.getHolder().getSurface());
                        b.addTarget(r.getSurface());
                        b.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
                        s.setRepeatingRequest(b.build(), null, background);
                    } catch (CameraAccessException | IllegalStateException | IllegalArgumentException e) {
                        fail(Ui.why(e));
                    }
                }

                @Override
                public void onConfigureFailed(CameraCaptureSession s) {
                    s.close();
                    fail(getString(R.string.camera_failed, -1));
                }
            }));
        } catch (CameraAccessException | IllegalStateException | IllegalArgumentException e) {
            fail(Ui.why(e));
        }
    }

    private void onFrame(ImageReader r) {
        Image img;
        try {
            img = r.acquireLatestImage();
        } catch (IllegalStateException closed) {
            return;
        }
        if (img == null) return;
        byte[] text = null;
        try {
            if (!done) {
                Image.Plane y = img.getPlanes()[0];
                text = Native.qrDecode(y.getBuffer(), img.getWidth(), img.getHeight(), y.getRowStride());
            }
        } catch (IllegalStateException e) {
            text = null;
        } finally {
            img.close();
        }
        if (text == null) return;
        if (done || !KeysActivity.startsWithKeyPrefix(text)) {
            // Another QR code in view (a Wi-Fi one, say) is no reason to stop looking.
            Arrays.fill(text, (byte) 0);
            return;
        }
        done = true;
        final byte[] found = text;
        runOnUiThread(() -> {
            closeCamera();
            try {
                String alias = KeysActivity.storeKey(found, getIntent().getBooleanExtra("auth", false));
                setResult(RESULT_OK, new Intent().putExtra("alias", alias));
                finish();
            } catch (Exception e) {
                fail(getString(R.string.import_failed) + ": " + Ui.why(e));
            }
        });
    }

    private void fail(String why) {
        hint.setText(why);
    }

    /** Closing the reader unmaps the frames, so it happens on the thread that decodes them. */
    private void closeCamera() {
        if (capture != null) capture.close();
        capture = null;
        if (camera != null) camera.close();
        camera = null;
        ImageReader r = reader;
        reader = null;
        if (r == null) return;
        Handler h = background;
        if (h == null || !h.post(r::close)) r.close();
    }
}

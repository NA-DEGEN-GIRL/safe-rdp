package io.github.na_degen_girl.saferdp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Runs the native self-test without the app's UI, from adb: {@code app_process} with this class,
 * the library's path and optionally a host and a test key file.
 */
public final class SelfTest {
    private SelfTest() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1 && args.length != 3) {
            System.err.println("usage: SelfTest <libsaferdp.so> [<host> <test key file>]");
            System.exit(2);
        }
        System.load(args[0]);
        System.out.print(new String(Native.selfTest(), StandardCharsets.UTF_8));
        if (args.length == 3) {
            byte[] key = Files.readAllBytes(Paths.get(args[2]));
            String target = args[1];
            try {
                byte[] r = Native.probe(target.getBytes(StandardCharsets.UTF_8), null, key);
                System.out.println("ok    session with " + new String(r, StandardCharsets.UTF_8));
            } catch (IllegalStateException e) {
                System.out.println("FAIL  session with " + target + ": " + e.getMessage());
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        }
        System.out.print(new String(Native.log(), StandardCharsets.UTF_8));
    }
}

# safe-rdp

Tailscale 위에서 쓰는 작고 감사(audit) 가능한 원격 데스크톱. **Windows와 Linux** 모두 호스트·뷰어로 동작합니다.

- **Rust 단일 실행 파일**, 서드파티 크레이트 없음. Windows는 `windows-sys`(Microsoft 공식 Win32 바인딩)만,
  Linux는 표준 라이브러리 + 실행 시 `dlopen`하는 시스템 OpenSSL(libcrypto)만 사용 (libX11/xcb도 링크하지 않고 X11 프로토콜을 직접 말함)
- 암호는 OS 구현만 사용 (Windows CNG, Linux OpenSSL 3). 직접 구현한 암호 코드는 HKDF(HMAC 몇 번 호출)뿐
- 화면 데이터를 **디스크에 쓰지 않음** (비트맵 캐시 없음, 프레임 버퍼는 RAM에 고정 후 종료 시 소거)

## 왜 만들었나 — 기본 RDP의 비트맵 캐시

`mstsc.exe`는 기본값으로 *영구 비트맵 캐싱*을 켜고, 원격 화면 타일을
`%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\` (`bcache*.bmc`, `Cache*.bin`)에 저장합니다.
이 파일들은 세션이 끝난 뒤에도 남고, 공개 포렌식 도구로 원격 화면 조각을 복원할 수 있습니다.
safe-rdp는 이런 영속 데이터를 만들지 않도록 설계했습니다.

## 빠른 시작 (Windows, GUI)

1. 빌드: `cargo build --release` → `target\release\safe-rdp.exe`를 양쪽 PC에 복사
2. `safe-rdp.exe`를 더블클릭하면 런처 창이 열립니다 (`safe-rdp gui`와 같음)
3. **키** 탭: 한쪽 PC에서 *키 만들기* → *복사*, 다른 PC의 키 탭에서 *가져오기*에 붙여넣기
   (복사한 키는 클립보드 기록·클라우드 동기화에서 제외되고 60초 뒤 자동으로 지워집니다)
4. 원격 PC: **이 PC 공유** 탭에서 *공유 시작*. 허용할 기능(제어, 클립보드, 파일, 소리, 화면 가리기)을 고릅니다
5. 로컬 PC: **연결** 탭의 Tailscale 기기 목록에서 원격 PC를 더블클릭

뷰어 창 위쪽의 **연결 바**에서 모니터·화질·배율 전환, 클립보드, 파일 보내기/받기, 소리, 화면 가리기,
전체 화면, 연결 끊기를 할 수 있습니다. 전체 화면에서는 화면 맨 위 가운데에 마우스를 대면 나타납니다.
호스트가 허용하지 않은 기능은 버튼이 숨겨지고, 연결이 끊기면 자동으로 다시 연결합니다
(1, 2, 4, 8, 16, 30초 간격, 2분 후 포기. 키가 틀리면 즉시 중단).

## 빠른 시작 (명령줄, Windows/Linux 공통)

```bash
safe-rdp keygen                # 키 생성 (한 번 출력되고 이 계정 전용으로 저장)
safe-rdp key import            # 다른 PC에서: 프롬프트에 붙여넣기 (명령줄 인자로는 받지 않음)
safe-rdp host                  # 원격 PC: 이 PC의 Tailscale IP에만 바인딩
safe-rdp devices               # tailnet 기기 목록
safe-rdp connect 원격PC이름     # MagicDNS 이름, Tailscale IP, host:port 모두 가능
```

| 단축키 (뷰어) | 동작 |
|---|---|
| `Ctrl+Alt+Enter` | 전체 화면 전환 |
| `Ctrl+Alt+End` | 원격에 Ctrl+Alt+Del 전송 (Windows 서비스 모드 + `--enable-sas`) |

창 모드에서는 Win 키, Alt+Tab, Alt+Esc, Ctrl+Esc가 로컬에 남고(mstsc 기본 동작과 동일),
전체 화면에서는 모든 키가 원격으로 갑니다. 한/영, 한자 키는 원격 IME로 그대로 전달됩니다.

## Linux

필요한 것: OpenSSL 3 런타임(`libssl3`, Ubuntu/Debian/Fedora 기본 설치), 호스트는 X11(XTEST, XFIXES, 가능하면 MIT-SHM),
소리는 PipeWire의 `pw-record`/`pw-play`.

- **데스크톱이 있는 Linux**: X11 세션에서 `safe-rdp host`. Wayland 세션(Ubuntu 기본 GNOME)은 Xwayland 창만
  캡처·입력할 수 있으므로 로그인 화면에서 "Ubuntu on Xorg"를 고르거나 아래 가상 화면을 쓰세요.
- **서버(모니터 없음)**: 가상 화면을 만들어 그 안의 프로그램을 공유합니다.

  ```bash
  safe-rdp host --virtual 1920x1080                      # 기본: 화면을 채우는 터미널
  safe-rdp host --virtual 1600x900 --session "xterm"     # 원하는 프로그램
  ```

  Xvfb는 TCP를 끈 채로, 무작위 쿠키(0600 파일, `$XDG_RUNTIME_DIR`의 0700 디렉터리)로 띄우며,
  호스트가 끝나면(Ctrl+C, SIGTERM, 비정상 종료 포함) Xvfb와 세션도 함께 종료됩니다.
  반대로 세션 프로그램이 끝나면(터미널에서 `exit`) 호스트도 멈춥니다. 그래서 `--session` 명령은
  백그라운드로 띄우지 말고 앞에서 계속 실행되게 하세요(`exec 프로그램`).
  같은 서버의 다른 사용자가 가상 화면을 가로채지 못하도록, 접속하는 X 서버가 우리가 띄운 Xvfb 프로세스인지
  매번 `SO_PEERCRED`로 확인하고 `/tmp/.X11-unix`의 소유자도 검사합니다.
- **뷰어**: `safe-rdp connect`가 X11 창을 엽니다(연결 바는 없고 단축키·명령줄 옵션으로 조작).
- 키는 `~/.config/safe-rdp/key`(디렉터리 0700, 파일 0600)에 저장됩니다. Windows의 DPAPI 같은 OS 암호화가 없으므로
  디스크 암호화를 권장합니다.

Linux 호스트에는 화면 가리기, Ctrl+Alt+Del, "복사한 파일 받기"가 없습니다(업로드는 됨).

## 기능

| 기능 | 설명 |
|---|---|
| 화질 | `균형`(기본): 사진·동영상처럼 복잡한 타일만 손실 압축(JPEG 방식, q80), 글자·UI는 무손실, 변화가 멈추면 0.3초 뒤 무손실로 다시 보냄. `저대역`: q50, 1.5초 뒤 보정. `무손실` |
| 배율 | 100/50/33/25% (`--downscale`), 4K 호스트를 노트북에서 보거나 느린 회선일 때 |
| 모니터 | 세션 중 모니터 전환, `all`은 모든 모니터를 한 화면으로(DXGI, 여러 GPU 포함). 회전·HDR 모니터 지원 |
| 클립보드 | 텍스트, 양쪽 모두 켜야 동작. 원격에서 온 텍스트는 Win+V 기록·클라우드 클립보드에서 제외 |
| 파일 | 뷰어 창에 끌어다 놓거나 *파일 보내기* → 호스트의 `다운로드\safe-rdp`. *복사한 파일 받기*: 호스트에서 탐색기로 복사(Ctrl+C)한 파일을 뷰어의 `다운로드\safe-rdp`로 |
| 소리 | 호스트의 시스템 소리(WASAPI 루프백 / PipeWire), IMA ADPCM 약 390 kbit/s, 지연 약 90–130 ms |
| 화면 가리기 | 원격 사용 중 호스트 모니터를 검게 가리고 호스트의 로컬 키보드·마우스를 막음 (Windows 호스트) |

파일 전송 안전장치:
- 이름은 경로가 아닌 단일 파일명만 허용. 끝이 `.`/공백인 이름, `CON`·`NUL` 같은 장치 이름, 확장자를 속이는
  양방향(RLO 등) 문자는 거부
- 무작위 이름의 숨김 `.srdp-*.part` 파일에 받은 뒤(받는 동안 다른 프로그램은 쓰거나 지울 수 없음)
  크기와 SHA-256이 맞을 때만 보이게 함. 기존 파일은 덮어쓰지 않음(`이름 (1).ext`)
- Windows에서는 받기 시작할 때부터 *인터넷에서 받은 파일* 표시(Mark of the Web)를 붙여 SmartScreen·Office 보호된
  보기가 적용됨. 표시를 붙일 수 없는 드라이브(FAT/exFAT)에서는 전송을 거부
- 뷰어는 *복사한 파일 받기*를 누른 뒤에만 파일을 받음(클릭당 최대 1000개, 1시간 이내)
- 서비스 모드에서 *복사한 파일 받기*는 SYSTEM이 아니라 로그인한 사용자 권한으로 파일을 열고,
  네트워크 경로(`\\server\...`)는 열지 않음. 로그인 화면에서는 동작하지 않음

화면 가리기는 뷰어가 보낸 입력만 통과시킵니다(이벤트마다 한 번만 쓰이는 무작위 표식). 화면 가리기를 켜기 전에 다른
프로그램이 엿본 표식은 무효이고, 한 호스트 프로세스에서 동시에 하나만 켜집니다.
한계: Ctrl+Alt+Del과 Win+L은 항상 Windows가 처리하므로 원격 PC 앞의 사람은 언제든 잠글 수 있습니다.
보안 데스크톱(UAC·잠금 화면), 시작 메뉴·알림 같은 셸 화면은 가림막 위로 올라올 수 있고, 마우스 포인터는 보입니다.
관리자 권한 창이 포커스를 가진 동안은 일반 권한 호스트가 로컬 입력을 막지 못합니다.

## 서비스 모드 (Windows: 잠금 화면 / 로그인 화면 / UAC)

`safe-rdp host`는 로그인된 사용자 세션 안에서 일반 권한으로 돌기 때문에
잠금 화면, UAC 보안 데스크톱, 관리자 권한 창에는 접근할 수 없습니다. 필요하면 서비스로 설치하세요
(런처의 *이 PC 공유* 탭 하단 버튼, 또는 관리자 터미널에서):

```bash
safe-rdp service install --enable-sas
safe-rdp service status
safe-rdp service uninstall
```

설치 시 하는 일:

1. 실행 파일을 `C:\Program Files\safe-rdp\`로 복사 (관리자만 교체 가능한 위치에서 SYSTEM으로 실행)
2. 키를 `%ProgramData%\safe-rdp\service.key`에 저장 — 폴더/파일 ACL은 SYSTEM·Administrators 전용, 내용은 DPAPI(머신 범위) 암호화
3. `SafeRdpHost` 서비스 등록(자동 시작, 실패 시 재시작)
4. 방화벽: 이 프로그램의 TCP 47300 인바운드를 **원격 IP 100.64.0.0/10, fd7a:115c:a1e0::/48에서만** 허용
5. `--enable-sas`를 준 경우에만 `SoftwareSASGeneration=1` 정책 설정 (서비스가 Ctrl+Alt+Del을 생성할 수 있게)

`%ProgramData%\safe-rdp`는 소유자가 SYSTEM/Administrators이고 관리자 전용 ACL이어야 합니다. 일반 사용자가 미리 만들어 둔
폴더라면 설치를 거부하니(키 탈취·바꿔치기 방지) 그 폴더를 지운 뒤 다시 설치하세요. 서비스와 에이전트도 시작할 때마다
같은 검사를 하고, 서비스는 에이전트를 끝낼 때 SYSTEM 전용 이벤트로 먼저 정상 종료(눌린 키 해제)를 요청합니다.
서비스 모드에서 `--files`를 켜면 업로드는 `%ProgramData%\safe-rdp\incoming`(관리자 전용)에 저장됩니다
(`--transfer-dir`로 변경 가능). 서비스(세션 0)는 활성 콘솔 세션에 SYSTEM 토큰으로 *에이전트*를 띄우고,
에이전트는 입력 데스크톱(Default ↔ Winlogon)을 따라가며 캡처/입력을 합니다.
로그: `%ProgramData%\safe-rdp\service.log`, `host.log` (IP와 이벤트만 기록, 화면·키 입력·파일 내용은 기록하지 않음.
4 MiB가 넘으면 `.old`로 넘기고 새로 시작하므로 디스크를 채우지 않음)

## 옵션

```
호스트 (host / service install):
  --bind <ip>              바인딩 주소 (기본: 이 PC의 Tailscale IPv4)
  --port <n>               TCP 포트 (기본 47300)
  --allow <ip>[,<ip>...]   이 주소들만 허용 (기본: 모든 Tailscale 피어)
  --allow-non-tailscale    Tailscale 대역 밖 바인딩/피어 허용 (비권장)
  --monitor <n|all>        공유할 모니터 (1 = 주 모니터, `safe-rdp monitors`로 확인)
  --fps <n>                최대 프레임레이트 (기본 30)
  --quality <q>            화질을 지정하지 않은 뷰어의 기본값: lossless | balanced | low
  --clipboard              텍스트 클립보드 공유 허용 (뷰어도 켜야 동작)
  --files                  파일 전송 허용 (업로드, 복사한 파일 받기)
  --transfer-dir <path>    업로드 저장 위치
  --audio                  뷰어가 이 PC의 소리를 듣도록 허용
  --privacy                뷰어가 이 PC 화면을 가리고 로컬 입력을 막도록 허용
  --view-only              키보드/마우스 입력 무시 (파일·화면 가리기도 불가)
  --virtual <WxH>          (Linux) 새 가상 X 화면(Xvfb)에서 실행
  --session <cmd>          (Linux, --virtual과 함께) 그 안에서 실행할 프로그램
  --key-file <path>        키 저장소 대신 텍스트 파일에서 키 읽기

뷰어 (connect):
  --fullscreen             전체 화면으로 시작
  --clipboard              텍스트 클립보드 공유 (호스트도 허용해야 함)
  --view-only              입력을 보내지 않음
  --downscale <2|3|4>      1/N 해상도로 받기
  --quality <q>            lossless | balanced(기본) | low
  --monitor <n|all>        볼 호스트 모니터 (1 = 주 모니터)
  --audio                  호스트 소리 재생
  --privacy                연결 중 호스트 화면 가리기
  --allow-capture          로컬 캡처 도구가 뷰어 창을 찍는 것을 허용 (기본은 차단)
  --key-file <path>        키 파일 사용
```

클립보드·파일·소리·화면 가리기는 모두 **호스트가 명시적으로 허용해야** 켜집니다(기본 꺼짐).
기타: `safe-rdp monitors`, `safe-rdp bench`(캡처/인코딩 속도), `safe-rdp key show|forget`,
`safe-rdp probe`(화면 없이 접속해 지연·대역폭·입력·설정·파일 전송을 시험하는 진단 도구).

## 보안 설계

### 전송 계층 (Tailscale 암호화 위에 한 겹 더)

Tailscale(WireGuard)이 이미 암호화하지만, 같은 tailnet의 다른 기기·ACL 실수·Tailscale 계정 탈취를
가정해 **애플리케이션 계층에서 독립적으로 인증·암호화**합니다.

```
C -> S  ClientHello = "SRDP" | ver(2) | nonce_c[32] | ECDH_P256_pub_c[64]
S -> C  ServerHello = "SRDP" | ver(2) | nonce_s[32] | ECDH_P256_pub_s[64] | server_confirm[32]
C -> S  client_confirm[32]

th  = SHA-256("safe-rdp/2 transcript" | ClientHello | ServerHello(confirm 제외))
prk = HKDF-Extract(salt = PSK, ikm = ECDH 공유 비밀(X 좌표, 빅엔디언))
okm = HKDF-Expand(prk, "safe-rdp/2 keys" | th, 128)
    = key_c2s | key_s2c | server_confirm | client_confirm
```

- **상호 인증**: 256비트 무작위 PSK를 모르면 confirm 값을 만들 수 없음. 서버가 먼저 증명하므로
  가짜 서버에게 클라이언트는 아무것도 보내지 않음.
- **전방 비밀성**: 매 세션 임시 ECDH 키. PSK가 나중에 유출돼도 녹화된 과거 트래픽은 복호화 불가.
- **오프라인 사전 공격 불가**: 키는 비밀번호가 아니라 `keygen`으로 만든 32바이트 난수만 허용.
- **레코드**: AES-256-GCM, 방향별 키, 64비트 카운터 논스(재전송·재정렬·변조 즉시 세션 종료),
  길이 필드도 AAD로 인증, 레코드 최대 32 MiB.
- Windows(CNG)와 Linux(OpenSSL)가 같은 바이트를 만드는지 NIST CAVS 벡터와 고정 AES-GCM 벡터로 양쪽에서 검증.

### 노출 면 최소화

- Tailscale 인터페이스에만 바인딩, 피어 주소가 Tailscale 대역이 아니면 핸드셰이크 전에 끊음
- 인증 전 파싱은 고정 길이 101바이트 하나뿐. 핸드셰이크 전체에 10초 마감(한 바이트씩 흘려 보내며 버티기 불가),
  동시 미인증 연결은 전체 8개·주소당 2개·(Tailscale 밖 IPv6는) /64당 4개, 실패한 주소는 1초 지연,
  인증 전 로그는 분당 몇 줄로 제한
- 인증 후에도 모든 메시지·타일 좌표·압축 해제 크기를 검증(한 메시지가 화면의 2배 넘게 그리게 하는 것도 거부).
  압축 해제(XPRESS Huffman, 손실 코덱, ADPCM)는 모두 메모리 안전한 Rust로 구현했고 잘못된 입력 수만 건으로 퍼징 테스트
- 상대가 보낸 이름·알림 문구는 제어/양방향 문자를 걸러서 표시·기록. 악의적인 호스트도 뷰어의 소리·화면 가리기를
  사용자 몰래 켜거나, 요청하지 않은 파일을 보내거나, 알림을 쏟아내 뷰어를 멈추게 할 수 없음
- view-only 세션은 입력뿐 아니라 호스트 클립보드 변경·파일 전송·화면 가리기도 불가
- 새 뷰어가 인증되면 기존 세션을 끊고 넘김(한 번에 한 세션), 끊길 때 눌려 있던 키/버튼을 모두 떼고 화면 가리기를 해제
- 호스트를 Ctrl+C/SIGTERM으로 멈춰도 같은 정리 과정을 거침

### 화면 데이터 잔존 방지

| 위험 | 대응 |
|---|---|
| 디스크 비트맵 캐시 | 없음. 화면 데이터를 파일로 쓰는 코드 자체가 없음 (진단용 `probe --snapshot`만 예외) |
| 스왑 | 프레임 버퍼를 `VirtualLock`/`mlock`으로 RAM에 고정, Linux는 코어 덤프에서도 제외 |
| 종료 후 메모리 잔존 | 프레임 버퍼·평문 레코드 버퍼·키를 해제 전에 0으로 덮어씀 |
| 다른 프로세스의 메모리 읽기 | Linux: `PR_SET_DUMPABLE=0`(같은 사용자의 ptrace·/proc/pid/mem 차단) |
| 로컬 스크린샷/녹화 | 뷰어 창에 `WDA_EXCLUDEFROMCAPTURE` (캡처 시 검게 보임, `--allow-capture`로 해제) |
| 키 저장 | Windows: DPAPI(사용자 범위), 서비스는 ACL + DPAPI(머신 범위). Linux: 0600 파일 |

## 구조

```
src/
  main.rs         명령줄
  channel.rs      핸드셰이크 + 암호화 레코드 계층        proto.rs   메시지 정의 (v2)
  crypto/         cng.rs (Windows) / openssl.rs (Linux, dlopen) + HKDF
  codec/          64x64 타일 diff, 좌측 예측 필터
    xpress.rs     [MS-XCA] XPRESS Huffman 압축/해제 (순수 Rust, cabinet.dll과 상호 호환 검증)
    lossy.rs      손실 타일 (YCbCr 4:2:0, DCT, 고정 Huffman; ffmpeg로 교차 검증)
  host.rs         호스트: 리스너, 세션, 흐름 제어, 설정, 파일, 소리
  viewer.rs       뷰어 공통: 접속, 송신 큐, 재연결 정책
  audio.rs        IMA ADPCM, 20 ms 패킷화
  files.rs        파일 송수신 (원자적, 체크섬, 덮어쓰기 없음)
  tailscale.rs    `tailscale status --json`으로 기기 목록     json.rs  엄격한 JSON 파서
  probe.rs        화면 없는 진단 클라이언트
  platform/
    windows/      dxgi(다중 출력·회전·HDR·dirty rect), capture(GDI 폴백), input, clipboard, desktop,
                  privacy(가림막·입력 차단), audio(WASAPI), service, keystore(DPAPI),
                  viewer + toolbar(연결 바), launcher(GUI)
    linux/        x11(소켓으로 직접 X11 프로토콜), capture(MIT-SHM), input(XTEST), clipboard, keymap,
                  viewer, xvfb(가상 화면), audio(PipeWire), keystore
```

흐름 제어: 호스트는 확인(ack)되지 않은 프레임이 2개 이상이면 다음 프레임을 만들지 않고
기다립니다. 회선이 느리면 프레임레이트가 자연히 떨어질 뿐 지연이 쌓이지 않고,
다음 프레임은 항상 최신 화면입니다.

성능(데스크톱 PC, 3840x2160): DXGI는 바뀐 영역만 복사(갱신당 0.5–6 ms),
4K 전체 프레임 인코딩 54 ms / 955 KiB(24비트 원본 대비 약 25배 작음), 디코딩 36 ms.
화면이 정지해 있으면 호스트 CPU는 거의 0입니다. Linux Xvfb 1080p 캡처(MIT-SHM)는 0.2 ms.

## 한계 (알고 쓰세요)

- **콘솔 세션 미러링 방식**입니다. RDP처럼 별도 세션을 만들지 않으므로 원격 PC 모니터에도
  같은 화면이 보입니다 → Windows 호스트는 *화면 가리기*(`--privacy`)로 가릴 수 있습니다.
- 스크롤처럼 화면 전체가 움직이는 경우 이동(move) 감지가 없어 바뀐 타일을 모두 다시 보냅니다
  (터미널 스크롤 1600x900 기준 약 35 Mbit/s). 느린 회선에서는 `--downscale 2`나 `저대역`을 쓰세요.
- 프린터/드라이브 리디렉션, 마이크, 다중 동시 뷰어는 없습니다.
- 일반 `host` 모드: 잠금 화면/UAC/관리자 권한 창은 조작 불가 → 서비스 모드 사용.
  Ctrl+Alt+Del은 서비스 모드 + `--enable-sas`에서만 동작합니다(Windows 정책상 다른 방법 없음).
- 메모리 보호는 *최선의 노력*입니다. 최대 절전 파일(hiberfil.sys), GPU 메모리, 커널 크래시 덤프까지
  막지는 못합니다. 디스크 전체 암호화(BitLocker/LUKS)를 함께 쓰세요.
- Tailscale ACL로 47300 포트에 접근할 수 있는 기기를 제한하면 한 겹 더 안전합니다.

## 테스트 상태

- 독립 리뷰 3회: 영역별 리뷰어가 찾은 문제(40건)를 다른 에이전트가 반박 검증한 뒤 고쳤고, 고친 코드도 다시 공격적으로
  검증해 남은 문제를 두 차례 더 고침
- 단위·통합 테스트: Windows 213개, Linux 172개 + X11/Xvfb 통합 테스트 14개 (`cargo test -- --ignored`)
  - 암호: SHA-256, HMAC(RFC 4231), HKDF(RFC 5869), AES-GCM(NIST), ECDH(NIST CAVS), CNG↔OpenSSL 바이트 고정 벡터
  - 코덱: [MS-XCA] 명세 예제, cabinet.dll 골든 스트림·상호 디코딩, 잘못된 스트림 3만 건 퍼징, 손실 코덱 PSNR·ffmpeg 교차 검증
  - 호스트 세션 종단 간(설정, 파일, 흐름 제어, 세션 교체), 뷰어 재연결 정책, 런처 명령줄, JSON/Tailscale 파싱
- 실제 기기 간 시험 (이 PC ↔ linux-host, Tailscale):
  - Windows 뷰어/probe → Linux 가상 화면 호스트: 핸드셰이크 28–84 ms, RTT 약 1 ms, 30 fps, 입력·파일(3 MiB, SHA-256 일치)·설정·소리 패킷 확인
  - Linux probe·X11 뷰어 → Windows 호스트(4K DXGI): 화질 3종, 배율, 모니터 전환, view-only 정책 거부,
    업로드(SHA-256 일치, Mark of the Web 확인), 핸드셰이크를 1바이트씩 끄는 공격이 마감에 끊기는 것 확인
  - Linux 가상 화면 호스트: 세션 프로그램이 끝나면 호스트가 멈추고 Xvfb·쿠키가 남지 않는 것 확인
- **아직 실제로 해 보지 않은 것**: 서비스 모드(관리자 권한 필요), 실제 모니터에 화면 가리기 켜기,
  소리를 실제로 들어 보는 청취 테스트, 여러 모니터·HDR 디스플레이, 실제 GNOME/Xorg 데스크톱 호스트.

# safe-rdp

Tailscale 위에서 쓰는 작고 감사(audit) 가능한 Windows 전용 원격 데스크톱.

- **Rust 단일 실행 파일**, 외부 의존성은 `windows-sys`(Microsoft 공식 Win32 바인딩) 하나뿐
- 암호화·압축·화면 캡처·입력 모두 **Windows 내장 API** 사용 (CNG, DPAPI, cabinet.dll, DXGI, GDI)
- 화면 데이터를 **디스크에 절대 쓰지 않음** (비트맵 캐시 없음, 프레임 버퍼는 RAM에 고정 후 종료 시 소거)

## 왜 만들었나 — 기본 RDP의 비트맵 캐시

`mstsc.exe`는 기본값으로 *영구 비트맵 캐싱*을 켜고, 원격 화면 타일을
`%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\` (`bcache*.bmc`, `Cache*.bin`)에 저장합니다.
이 파일들은 세션이 끝난 뒤에도 남고, 공개 포렌식 도구로 원격 화면 조각을 복원할 수 있습니다.
safe-rdp는 이런 영속 데이터를 만들지 않도록 설계했습니다.

## 빠른 시작

### 1. 빌드

```bash
cargo build --release
```

결과물: `target\release\safe-rdp.exe` (양쪽 PC에 같은 파일을 복사)

### 2. 키 만들기 (한쪽에서 한 번)

```bash
safe-rdp keygen
```

`srdp1-...` 형식의 키가 한 번 출력되고, 현재 Windows 계정 전용으로 DPAPI 암호화되어
`%APPDATA%\safe-rdp\key.dpapi`에 저장됩니다. 다른 PC에서:

```bash
safe-rdp key import
```

프롬프트에 붙여넣으면 됩니다(입력은 화면에 표시되지 않음). 키를 명령줄 인자로 받지 않는 것은
셸 히스토리에 남지 않게 하려는 의도입니다. 파이프(`type key.txt | safe-rdp key import`)도 됩니다.

### 3. 원격 PC(호스트)에서 화면 공유

```bash
safe-rdp host
```

자동으로 이 PC의 Tailscale IPv4(100.x.y.z)에만 바인딩합니다. 처음 실행 시 Windows 방화벽이
허용 여부를 물으면 허용하세요(서비스 모드는 Tailscale 대역만 허용하는 규칙을 자동으로 만듭니다).

### 4. 로컬 PC에서 접속

```bash
safe-rdp connect 원격PC이름
```

MagicDNS 이름, Tailscale IP, `host:port` 모두 가능합니다.

| 단축키 (뷰어) | 동작 |
|---|---|
| `Ctrl+Alt+Enter` | 전체 화면 전환 |
| `Ctrl+Alt+End` | 원격에 Ctrl+Alt+Del 전송 (서비스 모드 + `--enable-sas`) |

창 모드에서는 Win 키, Alt+Tab, Alt+Esc, Ctrl+Esc가 로컬에 남고(mstsc 기본 동작과 동일),
전체 화면에서는 모든 키가 원격으로 갑니다. 한/영, 한자 키는 원격 IME로 그대로 전달됩니다.

## 서비스 모드 (잠금 화면 / 로그인 화면 / UAC)

`safe-rdp host`는 로그인된 사용자 세션 안에서 일반 권한으로 돌기 때문에
잠금 화면, UAC 보안 데스크톱, 관리자 권한 창에는 접근할 수 없습니다.
원격 PC를 재부팅 후 로그인하거나 UAC 창을 눌러야 한다면 서비스로 설치하세요
(관리자 터미널에서, 키가 저장된 계정으로):

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

구조: 서비스(세션 0)가 활성 콘솔 세션에 SYSTEM 토큰으로 *에이전트*를 띄우고,
에이전트는 입력 데스크톱(Default ↔ Winlogon)을 따라가며 캡처/입력을 합니다.
에이전트는 kill-on-close Job Object로 서비스에 묶여 있어 서비스가 죽으면 같이 종료됩니다.
로그: `%ProgramData%\safe-rdp\service.log`, `host.log` (IP와 이벤트만 기록, 화면·키 입력은 기록하지 않음)

## 옵션

```
호스트 (host / service install):
  --bind <ip>              바인딩 주소 (기본: 이 PC의 Tailscale IPv4)
  --port <n>               TCP 포트 (기본 47300)
  --allow <ip>[,<ip>...]   이 주소들만 허용 (기본: 모든 Tailscale 피어)
  --allow-non-tailscale    Tailscale 대역 밖 바인딩/피어 허용 (비권장)
  --monitor <n|all>        공유할 모니터 (1 = 주 모니터, `safe-rdp monitors`로 확인)
  --fps <n>                최대 프레임레이트 (기본 30)
  --clipboard              텍스트 클립보드 공유 허용 (뷰어도 켜야 동작)
  --view-only              키보드/마우스 입력 무시
  --key-file <path>        키 저장소 대신 텍스트 파일에서 키 읽기

뷰어 (connect):
  --fullscreen             전체 화면으로 시작
  --clipboard              텍스트 클립보드 공유 (호스트도 허용해야 함)
  --view-only              입력을 보내지 않음
  --downscale <2|3|4>      1/N 해상도로 받기 (4K 호스트를 노트북에서 보거나 느린 회선일 때)
  --allow-capture          로컬 캡처 도구가 뷰어 창을 찍는 것을 허용 (기본은 차단)
  --key-file <path>        키 파일 사용
```

기타: `safe-rdp monitors`, `safe-rdp bench`(캡처/인코딩 속도 측정), `safe-rdp key show|forget`.

## 보안 설계

### 전송 계층 (Tailscale 암호화 위에 한 겹 더)

Tailscale(WireGuard)이 이미 암호화하지만, 같은 tailnet의 다른 기기·ACL 실수·Tailscale 계정 탈취를
가정해 **애플리케이션 계층에서 독립적으로 인증·암호화**합니다.

```
C -> S  ClientHello = "SRDP" | ver | nonce_c[32] | ECDH_P256_pub_c[64]
S -> C  ServerHello = "SRDP" | ver | nonce_s[32] | ECDH_P256_pub_s[64] | server_confirm[32]
C -> S  client_confirm[32]

th  = SHA-256("safe-rdp/1 transcript" | ClientHello | ServerHello(confirm 제외))
prk = HKDF-Extract(salt = PSK, ikm = ECDH 공유 비밀)
okm = HKDF-Expand(prk, "safe-rdp/1 keys" | th, 128)
    = key_c2s | key_s2c | server_confirm | client_confirm
```

- **상호 인증**: 256비트 무작위 PSK를 모르면 confirm 값을 만들 수 없음. 서버가 먼저 증명하므로
  가짜 서버에게 클라이언트는 아무것도 보내지 않음.
- **전방 비밀성**: 매 세션 임시 ECDH 키. PSK가 나중에 유출돼도 녹화된 과거 트래픽은 복호화 불가.
- **오프라인 사전 공격 불가**: 키는 비밀번호가 아니라 `keygen`으로 만든 32바이트 난수만 허용.
- **레코드**: AES-256-GCM, 방향별 키, 64비트 카운터 논스(재전송·재정렬·변조 즉시 세션 종료),
  길이 필드도 AAD로 인증, 레코드 최대 32 MiB.
- 모든 암호 연산은 Windows CNG(bcrypt.dll, FIPS 검증 구현). 직접 구현한 것은 HKDF(HMAC 몇 번 호출)뿐.

### 노출 면 최소화

- Tailscale 인터페이스에만 바인딩, 피어 주소가 Tailscale 대역이 아니면 핸드셰이크 전에 끊음
- 인증 전 파싱은 고정 길이 101바이트 하나뿐, 10초 타임아웃, 동시 미인증 연결 4개 제한, 실패 시 1초 지연
- 인증 후에도 모든 메시지·타일 좌표·압축 해제 크기를 검증
- 새 뷰어가 인증되면 기존 세션을 끊고 넘김(한 번에 한 세션), 끊길 때 눌려 있던 키/버튼을 모두 떼어 줌

### 화면 데이터 잔존 방지

| 위험 | 대응 |
|---|---|
| 디스크 비트맵 캐시 | 없음. 화면 데이터를 파일로 쓰는 코드 자체가 없음 |
| pagefile.sys로 스왑 | 프레임 버퍼를 `VirtualLock`으로 RAM에 고정 |
| 종료 후 메모리 잔존 | 프레임 버퍼·평문 레코드 버퍼·키를 해제 전에 0으로 덮어씀 |
| 로컬 스크린샷/녹화 | 뷰어 창에 `WDA_EXCLUDEFROMCAPTURE` (캡처 시 검게 보임, `--allow-capture`로 해제) |
| 클립보드 기록/클라우드 동기화 | 기본 꺼짐. 켜도 원격에서 온 텍스트는 Win+V 기록·클라우드 클립보드에서 제외 |
| 키 저장 | DPAPI(사용자 범위), 서비스는 ACL + DPAPI(머신 범위) |

## 구조

```
src/
  crypto.rs     CNG: SHA-256, HMAC, HKDF, ECDH P-256, AES-256-GCM, RNG
  channel.rs    핸드셰이크 + 암호화 레코드 계층
  proto.rs      메시지 정의
  codec.rs      64x64 타일 diff + 좌측 예측 필터 + XPRESS-Huffman(cabinet.dll), 무손실
  dxgi.rs       DXGI Desktop Duplication (화면이 바뀔 때만 깨어남)
  capture.rs    DXGI 우선, 실패 시 GDI 폴백 / 커서 모양 추적
  input.rs      SendInput 주입 (스캔코드 기반, 한/영·한자는 VK)
  desktop.rs    입력 데스크톱 추적 (Winlogon/UAC)
  server.rs     호스트: 리스너, 세션, 흐름 제어
  client.rs     뷰어: Win32 창, 렌더링, 키보드 훅, 마우스
  clipboard.rs  텍스트 클립보드 브리지 (선택)
  keystore.rs   키 생성/파싱/DPAPI 저장
  service.rs    Windows 서비스 + SYSTEM 에이전트
  mem.rs        페이지 잠금 버퍼
```

흐름 제어: 호스트는 확인(ack)되지 않은 프레임이 2개 이상이면 다음 프레임을 만들지 않고
기다립니다. 회선이 느리면 프레임레이트가 자연히 떨어질 뿐 지연이 쌓이지 않고,
다음 프레임은 항상 최신 화면입니다.

성능(데스크톱 PC, 3840x2160): DXGI 첫 프레임 20 ms(GDI는 137 ms),
4K 전체 프레임 인코딩 48 ms / 841 KiB(24비트 원본 대비 약 29배 작음), 디코딩 33 ms.
화면이 정지해 있으면 호스트 CPU는 거의 0입니다.

## 한계 (알고 쓰세요)

- **콘솔 세션 미러링 방식**입니다. RDP처럼 별도 세션을 만들지 않으므로 원격 PC 모니터에도
  같은 화면이 보입니다. 원격 PC 앞에 다른 사람이 있을 수 있다면 주의하세요.
- 무손실 코덱만 있습니다. 동영상·스크롤처럼 화면 전체가 바뀌면 대역폭을 많이 쓰고,
  느린 회선(DERP 릴레이 등)에서는 프레임레이트가 떨어집니다 → `--downscale 2` 권장.
- 소리, 파일 전송, 프린터/드라이브 리디렉션, 다중 모니터 동시 표시는 없습니다
  (`--monitor all`은 GDI로 전체 가상 화면을 한 장으로 보냄).
- 일반 `host` 모드: 잠금 화면/UAC/관리자 권한 창은 조작 불가 → 서비스 모드 사용.
- Ctrl+Alt+Del은 서비스 모드 + `--enable-sas`에서만 동작합니다.
- 회전된 디스플레이나 HDR(비 BGRA) 데스크톱은 GDI 경로(느림)로 동작합니다.
- 메모리 보호는 *최선의 노력*입니다. 최대 절전 파일(hiberfil.sys), GPU 메모리, 크래시 덤프까지
  막지는 못합니다. 디스크 전체 암호화(BitLocker)를 함께 쓰세요.
- Tailscale ACL로 47300 포트에 접근할 수 있는 기기를 제한하면 한 겹 더 안전합니다.

## 테스트 상태

- 단위 테스트 22개: CNG 알려진 답(KAT) 벡터(SHA-256, HMAC RFC 4231, HKDF RFC 5869, AES-GCM NIST),
  ECDH 합의·곡선 밖 점 거부, 핸드셰이크·잘못된 키·변조·재전송 거부, 메시지/코덱 왕복·손상 입력 거부,
  키 파싱·DPAPI 왕복, Tailscale 대역 판정
- `cargo test -- --ignored`: 마우스 절대좌표 주입이 정확한 픽셀에 떨어지는지, 로컬 Tailscale IP 감지
- 루프백 종단 간 테스트: 4K DXGI 스트리밍, `--downscale 2`, 잘못된 키 거부, 정상 종료
- **서비스 모드(설치·SYSTEM 에이전트·잠금 화면·SAS)는 관리자 권한이 필요해 개발 중 실행해 보지 못했습니다.**
  처음 쓸 때 `service.log`/`host.log`를 확인하세요.

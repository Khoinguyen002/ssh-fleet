# ssh-fleet (`sf`)

Tool dòng lệnh 1-file-binary (Go stdlib 100%, không dependency ngoài) để quản lý và SSH vào **cả VPS lẫn PC/Laptop cá nhân** trên Linux, macOS và Windows, kèm **E2EE Vault** và cơ chế **Wake / Soft-Sleep / Hard-Sleep / Keep-Awake**.

---

## Cài đặt & Setup chỉ với 1 lệnh

### Bước 1: Dựng Máy Chính (`Hub`) trên 1 con VPS có Public IP
```bash
curl -fsSL https://raw.githubusercontent.com/Khoinguyen002/ssh-fleet/main/install.sh | bash -s -- hub
```
Lệnh này sẽ tự tải `sf`, cài thành service chạy ngầm (`systemd`), tự sinh Token, và **in sẵn ra màn hình 1 dòng lệnh để mày copy chạy trên các máy khác**.

*(Tùy chọn: chỉ định port/token riêng: `... | bash -s -- hub --listen :8090 --token MAT_KHAU_CUA_MAY`)*

### Bước 2: Kết nối bất kỳ PC / Laptop / Máy cá nhân nào (1 lệnh)

- **Trên Linux / macOS:**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/Khoinguyen002/ssh-fleet/main/install.sh | bash -s -- join http://<IP-VPS>:8090 <TOKEN>
  ```
- **Trên Windows (PowerShell):**
  ```powershell
  $env:SF_HUB="http://<IP-VPS>:8090"; $env:SF_TOKEN="<TOKEN>"; irm https://raw.githubusercontent.com/Khoinguyen002/ssh-fleet/main/install.ps1 | iex
  ```

Xong 1 lệnh đó là máy tự cài `sf`, tự chạy Agent ngầm, tự báo danh về Hub và tự sync danh sách vào `~/.ssh/config`!

*(Nếu máy đó chỉ dùng để ngồi điều khiển chứ không cần mở SSH cho máy khác vào, thêm `--no-agent` ở cuối lệnh `sf join`.)*

---

## Cách hoạt động & Nơi lưu dữ liệu

```
                 ┌─────────────────────────────────────────┐
                 │      MÁY CHÍNH: 1 VPS có Public IP      │
                 │           Chạy lệnh: sf hub             │
                 │                                         │
                 │  DB lưu ngay trên VPS này tại:          │
                 │  ~/.config/ssh-fleet/hub-data/          │
                 │   ├── hub-nodes.json (Trạng thái, MAC)  │
                 │   └── vault.enc      (Vault+Key mã hóa) │
                 └───────▲─────────────────────────▲───────┘
                         │                         │
   (1) Luôn giữ kết nối   │                         │ (2) Kéo Vault / Wake /
       ngược (Outbound)  │                         │     Gõ: sf ssh pc-o-nha
                         │                         │
         ┌───────────────┴───────┐         ┌───────┴───────────────┐
         │   PC ở nhà / Laptop   │         │ Máy bất kỳ mày đang   │
         │   (Sau NAT / Wi-Fi)   │         │ ngồi (Mac/Win/Linux)  │
         │  Chạy lệnh: sf agent  │         │ Chạy lệnh: sf ssh ... │
         └───────────────────────┘         └───────────────────────┘
```

1. **SSH xuyên NAT cho PC/Laptop cá nhân + SSH trực tiếp cho VPS**:
   - PC/Laptop chạy `sf agent` (kết nối outbound về Hub) -> Gọi `sf ssh <tên-máy>` (hoặc `ssh <tên-máy>` qua `~/.ssh/config`) là xuyên thẳng vào SSH của máy đó.
2. **E2EE Vault (`vault.enc`) đồng bộ đa thiết bị**:
   - Mã hóa danh sách VPS, thiết bị, MAC address và toàn bộ **SSH Private Keys** bằng **PBKDF2-HMAC-SHA256 (210.000 vòng)** + **AES-256-GCM**.
   - Hub chỉ lưu bản sao đã mã hóa (`vault.enc`), không bao giờ thấy Master Password hay Private Key.
   - `sf vault init` -> `sf key import` -> `sf host add` -> `sf vault push` (trên máy mới chỉ cần `sf vault pull`).
3. **Wake / Sleep / Keep-Awake (kiểu AGY Studio)**:
   - **Keep-Awake** (`sf keep-awake <node> on|off`): Chống OS tự sleep (`systemd-inhibit` / `caffeinate` / `SetThreadExecutionState`).
   - **Soft-Sleep** (`sf sleep <node> --soft`): Khóa màn hình nhưng giữ keep-awake & Wi-Fi/TCP sống -> Gọi `sf wake <node>` từ bất kỳ đâu là bật dậy ngay tức thì.
   - **Hard-Sleep** (`sf sleep <node> --hard`): Suspend-to-RAM (S3) cấp OS.
   - **Wake-on-LAN qua LAN Relay** (`sf wake <node>`): Nếu máy đích đang Hard-Sleep/Offline, Hub tự nhờ một Agent khác đang Online trong **cùng subnet LAN** bắn gói **102-byte UDP Magic Packet** đánh thức máy đích.
   - **Wake-and-SSH** (`sf ssh <node> --wake`): Tự động đánh thức thiết bị, đợi nó online trên Hub rồi mở SSH.
4. **Fuzzy Search**:
   - Chạy `sf` hoặc `sf find <từ-khóa>` để lọc nhanh và chọn hành động (`ssh`, `wake`, `soft-sleep`, `hard-sleep`, `keep-awake`).

---

## Build thủ công từ source

```bash
GOOS=linux   GOARCH=amd64 go build -o dist/sf-linux-amd64 ./cmd/sf
GOOS=darwin  GOARCH=arm64 go build -o dist/sf-darwin-arm64 ./cmd/sf
GOOS=darwin  GOARCH=amd64 go build -o dist/sf-darwin-amd64 ./cmd/sf
GOOS=windows GOARCH=amd64 go build -o dist/sf-windows-amd64.exe ./cmd/sf
```


# 🛡️ ESP32 / ESP32-S3 Network-Wide DNS AdBlocker

Hệ thống lọc quảng cáo toàn mạng dựa trên vi điều khiển ESP32 / ESP32-S3. Giải pháp giá rẻ, tiết kiệm điện thay thế cho Pi-hole và AdGuard Home.

---

## 📋 Mở Đầu & Tính Năng
- **Tiết kiệm điện:** Sử dụng chip ESP32/ESP32-S3 công suất thấp (~1W).
- **Lọc quảng cáo cấp DNS:** Tự động chặn banner, tracker, pop-up cho toàn bộ thiết bị trong nhà (Điện thoại, Máy tính, Smart TV).
- **Dung lượng nhẹ:** Lưu trữ danh sách chặn nhị phân băm 40-bit FNV-1a trực tiếp trên bộ nhớ Flash.
- **Giao diện Web Dashboard:** Theo dõi lưu lượng truy vấn, cấu hình Custom Rules / Whitelist trực quan.

---

## 🛠️ 1. Cài Đặt Firmware & Blocklist

### Cách 1: Nạp qua VS Code / PlatformIO
1. Kết nối ESP32 với máy tính qua cổng USB.
2. Mở Terminal trong thư mục dự án VS Code và nạp Firmware & Phân vùng dữ liệu:
   ```bash
   pio run -t upload
   pio run -t uploadfs
Cách 2: Nạp qua Web Dashboard
Sau khi nạp Firmware, kết nối vào Wi-Fi phát ra từ ESP32 (C3-AdBlock-Setup) tại địa chỉ http://192.168.4.1 để cấu hình Wi-Fi nhà.
Tải tệp blocklist.bin về máy tính.
Mở Web Dashboard của ESP32 (http://<IP_ESP32>), chọn mục Blocklist -> Upload và tải tệp blocklist.bin lên.
🔌 2. Lắp Đặt Phần Cứng & Cấu Hình Modem/Router (FPT)
A. Kết Nối Phần Cứng
Rút ESP32 khỏi máy tính và cắm nguồn cố định qua củ sạc 5V hoặc cổng USB đằng sau Modem/Router.
Dữ liệu danh sách chặn đã lưu vĩnh viễn trên bộ nhớ Flash nên không bị mất khi rút điện.
B. Cấu Hình Trên Modem FPT (Áp dụng toàn mạng)
Bước 1: Gán IP Cố Định (Reserved IP / Static Lease)
Vào trang quản trị Modem (192.168.1.1 hoặc 192.168.100.1) -> LAN / Setup -> DHCP Static IP:
MAC Address: 98:c3:77:60:d6:88 (Địa chỉ MAC của ESP32)
IP Address: 192.168.100.88 (IP cố định cho ESP32)
Bấm Save / Apply.
Bước 2: Cài Đặt DNS Cho Toàn Mạng
Vào mục LAN -> DHCP Server:
Primary DNS (DNS 1): 192.168.100.88 (IP của ESP32)
Secondary DNS (DNS 2): 1.1.1.1 hoặc 8.8.8.8 (DNS dự phòng)
Bấm Save và Reboot (Khởi động lại) Modem.
🌐 3. Hướng Dẫn Sử Dụng & Tối Ưu
Tự động áp dụng: Tất cả thiết bị kết nối Wi-Fi nhà sẽ tự động gửi truy vấn qua ESP32 để chặn quảng cáo.
Chặn quảng cáo báo Việt Nam (Custom Rules): Truy cập Web Dashboard ([suspicious link removed]), vào Custom Rules / Add Domain và thêm các máy chủ quảng cáo nội địa:
eclick.vn (VnExpress)
admicro.vn (Dân Trí, Kênh14, CafeF)
admcdn.net
adtima.vn (Zalo / Zing)
ad.vnecdn.net
⚠️ 4. Khắc Phục Lỗi Thường Gặp (Troubleshooting)
Sự cố
Nguyên nhân
Cách khắc phục
Blocklist: 0 domains
Chưa nạp tệp blocklist.bin
Vào Web Dashboard -> Blocklist Upload -> Nạp file blocklist.bin hoặc chạy pio run -t uploadfs.
Total blocked: 0
Thiết bị vẫn lưu cache DNS cũ
Khởi động lại Modem. Bật/tắt lại Wi-Fi trên điện thoại/máy tính.
Một số máy vẫn lọt quảng cáo
Tính năng Private DNS / Secure DNS đang bật
• Android/iOS: Vào Cài đặt Mạng -> Private DNS -> Chọn Tắt (Off).<br>• Trình duyệt (Chrome/Edge): Cài đặt -> Security -> Tắt Use Secure DNS.
Lỗi build VS Code (ar.exe: No such file or directory)
Thư mục tạm .pio bị hỏng
Tắt VS Code, xóa thư mục ẩn .pio trong dự án và bấm Build lại.
Đổi địa chỉ IP ESP32
Modem cấp đổi IP do chưa gán IP tĩnh
Dùng ứng dụng Fing quét tìm IP mới của ESP32, sau đó thực hiện gán Reserved IP trên Modem.

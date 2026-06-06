import os
from core.compiler import ThreatCompiler

def main():
    compiler = ThreatCompiler()
    feeds_base_dir = "feeds"

    # 1. Kiểm tra xem thư mục gốc feeds/ có tồn tại không
    if not os.path.exists(feeds_base_dir):
        print(f"[-] Không tìm thấy thư mục gốc '{feeds_base_dir}'. Đang tự động tạo...")
        os.makedirs(feeds_base_dir)
        return

    # 2. Tự động quét tìm tất cả các thư mục con bên trong feeds/
    subfolders = [f.name for f in os.scandir(feeds_base_dir) if f.is_dir()]

    if not subfolders:
        print(f"[-] Thư mục '{feeds_base_dir}' đang trống. Chưa có nguồn tri thức nào được nạp.")
        return

    print(f"[*] Phát hiện {len(subfolders)} bộ nguồn tri thức: {', '.join(subfolders)}\n")

    # 3. Lặp qua từng thư mục và tự động nạp dữ liệu
    for folder_name in subfolders:
        folder_path = os.path.join(feeds_base_dir, folder_name)
        
        feed_display_name = folder_name.replace('_', ' ').title()
        
        compiler.ingest_yaml_feed(folder_path, feed_name=feed_display_name)

    print("\n" + "="*65)
    print("[+] TIẾN TRÌNH HOÀN TẤT: Toàn bộ tri thức đã được hợp nhất vào SQLite Database!")

if __name__ == "__main__":
    main()
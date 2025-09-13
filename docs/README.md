# Packet Parser

برنامه‌ای برای خواندن پکت‌های شبکه و ذخیره کردن SNI، IP و ... در دیتابیس

---

## شرح عملکرد

پکت پارسر از دو بخش پارسر و ارتباط با دیتابیس تشکیل شده که در ادامه به تفصیل توضیح داده میشوند:

1. `main.cpp`: فایل شروع برنامه که با استفاده از کتابخانه `libpcap` شروع به دریافت پکت‌ها از اینترفیس/فایل میکند و هر پکت را به تابع `packetHandler` جهت پارس کردن ارسال میکند. در این تابع با استفاده از ماژول‌های نوشته شده `dns.hpp` و `tls.hpp` پکت‌ها را پارس کرده و بعد از فیلتر کردن فقط مشخصات پکت‌های dns و tls client hello با ماژول `db.hpp` به دیتابیس ارسال میشوند.

2. `db.hpp`: این ماژول وظیفه اتصال به دیتابیس را دارد. پس از ایجاد شی‌ای از کلاس `DB`، تابع constructor وظیفه ایجاد جدول مربوطه را دارد.

    * فیلدهای جدول بصورت زیر است:

        ```sql
        CREATE TABLE IF NOT EXISTS testreg(
            id INT PRIMARY KEY AUTO_INCREMENT,
            timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
            appname VARCHAR(10),
            packettype ENUM('DNS', 'TLS'),
            servername TEXT,
            ip VARCHAR(15),
            port SMALLINT UNSIGNED
        )
        ```

    * در این کلاس متدهای زیر پکت مربوطه را میگیرند و به دیتابیس ارسال میکنند:

        ```cpp
        bool DB::insert_dns(Packet dnsPacket);
        bool DB::insert_tls(Packet tlsPacket)
        ```

3. `dns.hpp` / `tls.hpp`: در این دو ماژول، استراکچرهایی برای فیلد‌های مربوط به هر پکت تعریف شده که توابع زیر با استفاده از این استراکچرها پکت‌ها را پارس میکنند:

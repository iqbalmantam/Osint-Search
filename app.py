import streamlit as st
import requests
import urllib.parse
import pandas as pd

# Konfigurasi Halaman (Clean Layout)
st.set_page_config(
    page_title="OSINT Search Engine Workstation",
    page_icon="🔍",
    layout="wide"
)

# Header Utama
st.title("🔍 OSINT Search Engine Workstation")
st.markdown("Pusat pencarian intelijen sumber terbuka (*Open Source Intelligence*) terpadu dengan verifikasi real-time dan modul penelusuran mendalam.")
st.markdown("---")

# Pengaturan Kategori Target (Di Main Container - Tanpa Sidebar)
col_mode, col_info = st.columns([2, 1])
with col_mode:
    search_type = st.selectbox(
        "Pilih Kategori Target Investigasi:",
        [
            "Username Live Checker", 
            "IP / Domain Geolocation & Lookup", 
            "Subdomain & Certificate Recon (crt.sh)",
            "Google Dork Generator", 
            "Email & Phone Recon"
        ]
    )
with col_info:
    st.info("💡 **Tips:** Pastikan format target yang dimasukkan sesuai dengan kategori investigasi yang dipilih.")

st.markdown("")

# Input Kueri Utama
query = st.text_input(
    "Masukkan Kueri Target (Username, Domain, IP, Email, atau Kata Kunci):",
    placeholder="Contoh: joko_susilo / detik.com / 8.8.8.8 / target@domain.com"
).strip()

st.markdown("---")

# Tombol Eksekusi
if st.button("Jalankan Investigasi OSINT", type="primary", use_container_width=True):
    if not query:
        st.warning("⚠️ Mohon masukkan kueri target terlebih dahulu!")
    else:
        st.success(f"Menjalankan modul pencarian untuk target: **{query}**")
        st.markdown("")
        
        # 1. Modul Username Live Checker
        if search_type == "Username Live Checker":
            st.subheader("🌐 Pengecekan Eksistensi Username (Live HTTP Status Check)")
            st.info("Sistem memverifikasi status ketersediaan profil publik secara langsung melalui permintaan HTTP.")

            platforms = {
                "GitHub": f"https://github.com/{query}",
                "Instagram": f"https://www.instagram.com/{query}/",
                "X (Twitter)": f"https://twitter.com/{query}",
                "TikTok": f"https://www.tiktok.com/@{query}",
                "Telegram": f"https://t.me/{query}",
                "Reddit": f"https://www.reddit.com/user/{query}"
            }

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }

            results = []
            progress_bar = st.progress(0)
            total = len(platforms)

            for i, (plat, url) in enumerate(platforms.items()):
                status_text = "Tidak Diketahui / Proteksi Bot"
                badge = "⚠️ Netral"
                try:
                    response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
                    if response.status_code == 200:
                        status_text = "Aktif / Ditemukan (200 OK)"
                        badge = "🟢 Ditemukan"
                    elif response.status_code == 404:
                        status_text = "Tidak Ditemukan (404 Not Found)"
                        badge = "🔴 Tidak Ada"
                    else:
                        status_text = f"Respon Server ({response.status_code})"
                        badge = "🟡 Terbatas"
                except requests.exceptions.Timeout:
                    status_text = "Koneksi Timeout"
                    badge = "⏱️ Timeout"
                except Exception:
                    status_text = "Diblokir / Proteksi Keamanan"
                    badge = "🛡️ Dilindungi"

                results.append({
                    "Platform": plat,
                    "Status Akun": badge,
                    "Keterangan": status_text,
                    "URL Tautan": url
                })
                progress_bar.progress((i + 1) / total)

            df_res = pd.DataFrame(results)
            st.dataframe(df_res, use_container_width=True)

        # 2. Modul IP / Domain Geolocation & Lookup
        elif search_type == "IP / Domain Geolocation & Lookup":
            st.subheader("🌍 Informasi Jaringan, ASN, & Geolocation Real-Time")
            clean_query = query.replace("https://", "").replace("http://", "").split("/")[0]
            
            with st.spinner("Mengambil data jaringan dari server lookup global..."):
                try:
                    is_ip = all(part.isdigit() for part in clean_query.split(".") if part) and len(clean_query.split(".")) == 4
                    
                    if is_ip:
                        api_url = f"http://ip-api.com/json/{clean_query}"
                    else:
                        api_url = f"https://ipapi.co/{clean_query}/json/"

                    res = requests.get(api_url, timeout=7)
                    if res.status_code == 200:
                        data = res.json()
                        if "error" in data:
                            st.error(f"Gagal dari API: {data.get('reason', 'Target tidak valid')}")
                        else:
                            st.json(data)
                            
                            if is_ip and "country" in data:
                                st.markdown("### Ringkasan Lokasi:")
                                st.markdown(f"- **Negara:** {data.get('country', '-')}")
                                st.markdown(f"- **Wilayah/Kota:** {data.get('regionName', '-')}, {data.get('city', '-')}")
                                st.markdown(f"- **ISP / Organisasi:** {data.get('isp', '-')}, {data.get('org', '-')}")
                    else:
                        st.error("Gagal terhubung ke layanan lookup jaringan publik.")
                except Exception as e:
                    st.error(f"Terjadi kesalahan saat memproses kueri jaringan: {e}")

        # 3. Modul Baru: Subdomain & Certificate Transparency Recon (crt.sh)
        elif search_type == "Subdomain & Certificate Recon (crt.sh)":
            st.subheader("🛡️ Subdomain & Certificate Transparency Intelligence")
            clean_domain = query.replace("https://", "").replace("http://", "").split("/")[0]
            st.info(f"Menganalisis riwayat sertifikat SSL/TLS untuk domain utama: **{clean_domain}**")
            
            crt_url = f"https://crt.sh/?q={clean_domain}&output=json"
            
            with st.spinner("Mengambil riwayat sertifikat publik dari crt.sh..."):
                try:
                    headers = {"User-Agent": "Mozilla/5.0"}
                    response = requests.get(crt_url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        if len(data) == 0:
                            st.warning("Tidak ditemukan data subdomain/sertifikat untuk target tersebut.")
                        else:
                            # Ekstraksi dan pembersihan subdomain unik
                            subdomains = set()
                            for entry in data:
                                name_value = entry.get("name_value", "")
                                for sub in name_value.split("\n"):
                                    subdomains.add(sub.strip().lower())
                            
                            df_sub = pd.DataFrame(list(subdomains), columns=["Daftar Subdomain / Common Name"])
                            st.success(kamus_sukses := f"Berhasil menemukan {len(df_sub)} entri unik terkait domain tersebut!")
                            st.dataframe(df_sub, use_container_width=True)
                            
                            # Tautan langsung web crt.sh
                            direct_link = f"https://crt.sh/?q={clean_domain}"
                            st.markdown(f"👉 **Buka Tampilan Lengkap di crt.sh:** [Klik di sini]({direct_link})")
                    else:
                        st.error("Gagal mengambil data dari server crt.sh. Silakan gunakan tautan langsung di bawah.")
                        st.markdown(f"👉 [Buka crt.sh secara manual](https://crt.sh/?q={clean_domain})")
                except Exception as e:
                    st.warning(f"Respon server crt.sh tertunda atau memerlukan query manual. Silakan akses langsung: [crt.sh/?q={clean_domain}](https://crt.sh/?q={clean_domain})")

        # 4. Modul Google Dork Generator
        elif search_type == "Google Dork Generator":
            st.subheader("🔎 Konstruksi Google Dork Lanjutan")
            st.markdown("Gunakan tautan cepat di bawah untuk melakukan *deep search* langsung ke indeks Google:")
            
            dorks = {
                "Dokumen Sensitif & Publik (PDF/Doc/Xls)": f'site:{query} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:xlsx',
                "Direktori Terbuka / Indeks Server": f'site:{query} intitle:"index of"',
                "File Konfigurasi / Database (Env/Sql/Json)": f'site:{query} filetype:env OR filetype:sql OR filetype:json OR filetype:txt',
                "Pejabat / Karyawan / Profil Terkait": f'"{query}" site:linkedin.com OR site:instagram.com OR site:facebook.com',
                "Jejak Pendidikan / Akademik": f'"{query}" site:pddikti.kemdikbud.go.id OR site:academia.edu OR site:researchgate.net'
            }
            
            for title, dork_query in dorks.items():
                encoded_dork = urllib.parse.quote(dork_query)
                search_url = f"https://www.google.com/search?q={encoded_dork}"
                st.markdown(f"**{title}**  \n`{dork_query}`  \n👉 [Buka Pencarian Google]({search_url})")
                st.markdown("---")

        # 5. Modul Email & Phone Recon
        elif search_type == "Email & Phone Recon":
            st.subheader("📧 & 📱 Analisis Jejak Kontak & Domain")
            if "@" in query:
                domain_part = query.split("@")[-1]
                local_part = query.split("@")[0]
                st.info(f"Menganalisis komponen email untuk struktur: **Domain [{domain_part}] | Akun [{local_part}]**")
                
                st.markdown("### Alat Verifikasi Eksternal Terpercaya:")
                st.markdown(f"1. **Pemeriksaan Mail Exchange (MX) & DNS Domain:** [MXToolbox](https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain_part})")
                st.markdown(f"2. **Pemeriksaan Reputasi / Kebocoran Kredensial:** [HaveIBeenPwned](https://haveibeenpwned.com/) (Cari manual dengan email: `{query}`)")
                st.markdown(f"3. **Pemeriksaan Keamanan Domain (SSL/TLS Report):** [SSL Labs](https://www.ssllabs.com/ssltest/analyze.html?d={domain_part})")
            else:
                clean_phone = query.replace("+", "").replace(" ", "").replace("-", "")
                st.info(f"Menganalisis format nomor kontak: **{query}** (Format bersih: `{clean_phone}`)")
                
                st.markdown("### Tautan Akses & Navigasi Cepat:")
                st.markdown(f"- **Buka Chat WhatsApp Langsung:** [Kirim Pesan WhatsApp](https://wa.me/{clean_phone})")
                st.markdown(f"- **Pemeriksaan Kode Negara & Operator:** [Country Code Lookup](https://www.countrycode.org/)")
                st.warning("⚠️ Untuk pengecekan nama pemilik nomor, disarankan menggunakan verifikasi manual pada aplikasi direktori seluler yang aman.")

import streamlit as st
import requests
import urllib.parse
import pandas as pd
import re

# Konfigurasi Halaman (Clean Layout - Tanpa Sidebar & Header Bawaan)
st.set_page_config(
    page_title="Osint-Pro | CTI & Intelligence Workstation",
    page_icon="🛡️",
    layout="wide"
)

# Sembunyikan elemen bawaan Streamlit (Header, Footer, MainMenu)
hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# Header Utama Workstation
st.title("🛡️ Osint-Pro : CTI & Intelligence Workstation")
st.markdown("Pusat intelijen ancaman siber (*Cyber Threat Intelligence*) dan investigasi sumber terbuka terpadu.")
st.markdown("---")

# Kotak Search Engine Target Tunggal (Cerdas & Otomatis)
query = st.text_input(
    "Masukkan Kueri Target (Username, Domain / URL, Alamat IP, Email, atau Entitas):",
    placeholder="Contoh: target_name / detik.com / 8.8.8.8 / target@domain.com"
).strip()

st.markdown("---")

if query:
    st.success(f"Menjalankan pipeline CTI & OSINT untuk target: **{query}**")
    st.markdown("")

    # Tab Modul Investigasi Menyerupai Struktur Osint-Pro
    tab_user, tab_domain, tab_ip, tab_email, tab_cti = st.tabs([
        "👤 Identity & Social Recon", 
        "🌐 Domain & Subdomain (crt.sh)", 
        "🌍 Network & Geolocation", 
        "📧 Contact & Breach Check", 
        "🤖 CTI & Threat Profiling"
    ])

    # 1. Modul Identity & Social Recon
    with tab_user:
        st.subheader("Pengecekan Profil Publik & Jejak Digital")
        st.write("Melakukan verifikasi eksistensi akun target secara real-time pada berbagai platform publik utama.")
        
        platforms = {
            "GitHub": f"https://github.com/{query}",
            "Instagram": f"https://www.instagram.com/{query}/",
            "X (Twitter)": f"https://twitter.com/{query}",
            "TikTok": f"https://www.tiktok.com/@{query}",
            "Telegram": f"https://t.me/{query}",
            "LinkedIn": f"https://www.linkedin.com/in/{query}",
            "Reddit": f"https://www.reddit.com/user/{query}"
        }

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        results = []
        
        for plat, url in platforms.items():
            status = "Netral / Terproteksi"
            try:
                resp = requests.get(url, headers=headers, timeout=4, allow_redirects=True)
                if resp.status_code == 200:
                    status = "🟢 Ditemukan (200 OK)"
                elif resp.status_code == 404:
                    status = "🔴 Tidak Ditemukan (404)"
                else:
                    status = f"🟡 Respon Server ({resp.status_code})"
            except:
                status = "🛡️ Rate-Limited / Timeout"
            results.append({"Platform": plat, "Status Akun": status, "Tautan Akses": url})
            
        st.dataframe(pd.DataFrame(results), use_container_width=True)

    # 2. Modul Domain & Subdomain Recon (crt.sh)
    with tab_domain:
        st.subheader("Subdomain & Certificate Transparency Intelligence")
        clean_domain = query.replace("https://", "").replace("http://", "").split("/")[0]
        st.write(f"Menganalisis riwayat sertifikat SSL/TLS publik untuk pemetaan permukaan serangan domain: **{clean_domain}**")
        
        try:
            crt_url = f"https://crt.sh/?q={clean_domain}&output=json"
            response = requests.get(crt_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=8)
            if response.status_code == 200 and response.content:
                data = response.json()
                subdomains = set()
                for entry in data:
                    for sub in entry.get("name_value", "").split("\n"):
                        subdomains.add(sub.strip().lower())
                df_sub = pd.DataFrame(list(subdomains), columns=["Daftar Subdomain Unik"])
                st.success(f"Berhasil menemukan {len(df_sub)} entri subdomain aktif!")
                st.dataframe(df_sub, use_container_width=True)
            else:
                st.info("Tidak ada data subdomain terekam.")
                st.markdown(f"👉 [Buka crt.sh secara manual](https://crt.sh/?q={clean_domain})")
        except Exception as e:
            st.warning(f"Koneksi ke crt.sh dibatasi: {e}")
            st.markdown(f"👉 [Buka crt.sh secara manual](https://crt.sh/?q={clean_domain})")

    # 3. Modul Network & Geolocation
    with tab_ip:
        st.subheader("Infrastruktur Jaringan, ASN, & Geolocation Lookup")
        clean_ip = query.replace("https://", "").replace("http://", "").split("/")[0]
        
        try:
            is_ip = all(part.isdigit() for part in clean_ip.split(".") if part) and len(clean_ip.split(".")) == 4
            api_url = f"http://ip-api.com/json/{clean_ip}" if is_ip else f"https://ipapi.co/{clean_ip}/json/"
            
            res = requests.get(api_url, timeout=7)
            if res.status_code == 200:
                data = res.json()
                st.json(data)
            else:
                st.error("Gagal mengambil data geolokasi jaringan.")
        except Exception as e:
            st.error(f"Gagal memproses kueri jaringan: {e}")

    # 4. Modul Contact & Breach Check
    with tab_email:
        st.subheader("Analisis Jejak Kontak & Reputasi Domain")
        if "@" in query:
            domain_part = query.split("@")[-1]
            st.markdown(f"- **Domain Email Target:** `{domain_part}`")
            st.markdown(f"- **Pemeriksaan MX Record & DNS:** [MXToolbox](https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain_part})")
            st.markdown(f"- **Pemeriksaan Kebocoran Data (Breach):** [HaveIBeenPwned](https://haveibeenpwned.com/) (Cari manual dengan email: `{query}`)")
            st.markdown(f"- **Analisis SSL/TLS Server:** [SSL Labs](https://www.ssllabs.com/ssltest/analyze.html?d={domain_part})")
        else:
            clean_phone = query.replace("+", "").replace(" ", "").replace("-", "")
            st.markdown(f"- **Tautan WhatsApp Langsung:** [Kirim Pesan](https://wa.me/{clean_phone})")
            st.markdown(f"- **Pemeriksaan Kode Negara & Operator:** [Country Code Lookup](https://www.countrycode.org/)")

    # 5. Modul CTI & Threat Profiling (Google Dorks & Hipotesis Ancaman)
    with tab_cti:
        st.subheader("Cyber Threat Intelligence & Advanced Dorking")
        st.write("Konstruksi dork tingkat lanjut untuk mengidentifikasi kebocoran dokumen, direktori terbuka, atau eksposur data sensitif.")
        
        dorks = {
            "Dokumen Sensitif (PDF / Doc / Xls)": f'site:{query} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:xlsx',
            "Direktori Terbuka / Indeks Server": f'site:{query} intitle:"index of"',
            "File Konfigurasi / Database (.env / .sql / .json)": f'site:{query} filetype:env OR filetype:sql OR filetype:json OR filetype:txt',
            "Penyebutan di Media Sosial & Profesional": f'"{query}" site:linkedin.com OR site:instagram.com OR site:facebook.com',
            "Verifikasi Akademik / PDDikti": f'"{query}" site:pddikti.kemdikbud.go.id OR site:academia.edu OR site:researchgate.net'
        }
        
        for title, dork_q in dorks.items():
            search_url = f"https://www.google.com/search?q={urllib.parse.quote(dork_q)}"
            st.markdown(f"**{title}**  \n`{dork_q}`  \n👉 [Buka Penelusuran Google CTI]({search_url})")
            st.markdown("---")

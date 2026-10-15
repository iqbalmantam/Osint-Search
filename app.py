import streamlit as st
import requests
import urllib.parse
import pandas as pd
import re

# Konfigurasi Halaman (Clean Layout - Tanpa Sidebar & Header Bawaan)
st.set_page_config(
    page_title="OSINT Smart Search Engine",
    page_icon="🔍",
    layout="wide"
)

hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# Header Utama Minimalis
st.title("🔍 OSINT Smart Search Engine")
st.markdown("Masukkan target apa saja. Sistem cerdas akan mendeteksi tipe data dan menjalankan investigasi secara otomatis.")
st.markdown("---")

# Kotak Search Engine Tunggal
query = st.text_input(
    "Search Engine Target:",
    placeholder="Ketik IP, Domain, Email, No HP, atau Username... (Contoh: 8.8.8.8, detik.com, joko_susilo)"
).strip()

st.markdown("---")

# Fungsi Deteksi Tipe Kueri Cerdas
def detect_query_type(q):
    if not q:
        return "empty"
    # Cek apakah format IP Address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", q):
        return "ip"
    # Cek apakah Email
    elif "@" in q and "." in q.split("@")[1]:
        return "email"
    # Cek apakah Nomor Telepon
    elif re.match(r"^\+?[0-9\-\s]{8,15}$", q):
        return "phone"
    # Cek apakah Domain / URL
    elif "." in q and " " not in q and not q.startswith("@"):
        return "domain"
    # Selebihnya dianggap Username / Kata Kunci Umum
    else:
        return "username_or_keyword"

if query:
    q_type = detect_query_type(query)
    
    # 1. Jika terdeteksi sebagai IP Address
    if q_type == "ip":
        st.success("🎯 **Deteksi Otomatis:** Target adalah sebuah **Alamat IP**.")
        with st.spinner("Mengambil data geolokasi & jaringan..."):
            try:
                res = requests.get(f"http://ip-api.com/json/{query}", timeout=7)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Negara", data.get("country", "-"))
                        col2.metric("Wilayah", data.get("regionName", "-"))
                        col3.metric("Kota", data.get("city", "-"))
                        
                        st.json(data)
                    else:
                        st.error("Data IP tidak ditemukan atau privat.")
                else:
                    st.error("Gagal terhubung ke server lookup IP.")
            except Exception as e:
                st.error(f"Koneksi error: {e}")

    # 2. Jika terdeteksi sebagai Domain
    elif q_type == "domain":
        clean_domain = query.replace("https://", "").replace("http://", "").split("/")[0]
        st.success(f"🎯 **Deteksi Otomatis:** Target adalah sebuah **Domain / Website** (`{clean_domain}`).")
        
        tab1, tab2, tab3 = st.tabs(["🌍 Geolocation / Server", "🛡️ Subdomain Recon (crt.sh)", "🔎 Google Dork Target"])
        
        with tab1:
            try:
                res = requests.get(f"https://ipapi.co/{clean_domain}/json/", timeout=7)
                if res.status_code == 200:
                    st.json(res.json())
                else:
                    st.warning("Lookup domain terbatas.")
            except:
                st.error("Gagal mengambil data domain.")
                
        with tab2:
            st.write("Mencari riwayat sertifikat & subdomain publik...")
            try:
                crt_url = f"https://crt.sh/?q={clean_domain}&output=json"
                response = requests.get(crt_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
                if response.status_code == 200 and response.content:
                    data = response.json()
                    subdomains = set()
                    for entry in data:
                        for sub in entry.get("name_value", "").split("\n"):
                            subdomains.add(sub.strip().lower())
                    df_sub = pd.DataFrame(list(subdomains), columns=["Subdomain Ditemukan"])
                    st.dataframe(df_sub, use_container_width=True)
                else:
                    st.info("Tidak ada data subdomain terekam.")
            except:
                st.markdown(f"👉 [Buka crt.sh secara manual](https://crt.sh/?q={clean_domain})")
                
        with tab3:
            dorks = {
                "Dokumen Sensitif (PDF/Doc)": f'site:{clean_domain} filetype:pdf OR filetype:doc OR filetype:xls',
                "Direktori Terbuka": f'site:{clean_domain} intitle:"index of"',
                "File Konfigurasi": f'site:{clean_domain} filetype:env OR filetype:sql OR filetype:json'
            }
            for title, dork_q in dorks.items():
                url = f"https://www.google.com/search?q={urllib.parse.quote(dork_q)}"
                st.markdown(f"- **{title}**: [`{dork_q}`]({url})")

    # 3. Jika terdeteksi sebagai Email
    elif q_type == "email":
        domain_part = query.split("@")[-1]
        st.success("🎯 **Deteksi Otomatis:** Target adalah sebuah **Alamat Email**.")
        st.markdown(f"### Analisis Komponen Email: `{query}`")
        st.markdown(f"- **Pemeriksaan MX Record Domain ({domain_part}):** [MXToolbox](https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain_part})")
        st.markdown(f"- **Pemeriksaan Kebocoran Data (Breach):** [HaveIBeenPwned](https://haveibeenpwned.com/) (Cari manual dengan email tersebut)")

    # 4. Jika terdeteksi sebagai Nomor Telepon
    elif q_type == "phone":
        clean_phone = query.replace("+", "").replace(" ", "").replace("-", "")
        st.success("🎯 **Deteksi Otomatis:** Target adalah sebuah **Nomor Telepon**.")
        st.markdown(f"- **Chat WhatsApp Langsung:** [Buka WhatsApp](https://wa.me/{clean_phone})")
        st.markdown(f"- **Kode Negara / Operator:** [Country Code Lookup](https://www.countrycode.org/)")

    # 5. Jika terdeteksi sebagai Username / Kata Kunci Umum
    else:
        st.success(f"🎯 **Deteksi Otomatis:** Target adalah **Username / Kata Kunci** (`{query}`).")
        
        tab_user, tab_dork = st.tabs(["🌐 Live Username Check", "🔎 Deep Google Dork"])
        
        with tab_user:
            st.write("Memeriksa eksistensi akun di platform publik secara real-time...")
            platforms = {
                "GitHub": f"https://github.com/{query}",
                "Instagram": f"https://www.instagram.com/{query}/",
                "X (Twitter)": f"https://twitter.com/{query}",
                "TikTok": f"https://www.tiktok.com/@{query}",
                "Telegram": f"https://t.me/{query}",
                "Reddit": f"https://www.reddit.com/user/{query}"
            }
            headers = {"User-Agent": "Mozilla/5.0"}
            results = []
            
            for plat, url in platforms.items():
                status = "Netral"
                try:
                    resp = requests.get(url, headers=headers, timeout=4, allow_redirects=True)
                    status = "🟢 Ditemukan (200)" if resp.status_code == 200 else "🔴 Tidak Ada (404)"
                except:
                    status = "🛡️ Dilindungi / Timeout"
                results.append({"Platform": plat, "Status": status, "URL": url})
                
            st.dataframe(pd.DataFrame(results), use_container_width=True)
            
        with tab_dork:
            dorks = {
                "Penyebutan di Media Sosial": f'"{query}" site:linkedin.com OR site:instagram.com OR site:twitter.com',
                "Dokumen Publik / Akademik": f'"{query}" site:pddikti.kemdikbud.go.id OR site:academia.edu'
            }
            for title, dork_q in dorks.items():
                url = f"https://www.google.com/search?q={urllib.parse.quote(dork_q)}"
                st.markdown(f"- **{title}**: [`{dork_q}`]({url})")

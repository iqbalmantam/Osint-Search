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
st.markdown("Cyber Threat Intelligence & Open Source Intelligence Workstation berbasis Python.")
st.markdown("---")

# Kotak Search Engine Tunggal Utama
query = st.text_input(
    "Osint-Pro Search Engine:",
    placeholder="Masukkan target (Username, Domain, IP, Email, atau Kata Kunci Investigasi)..."
).strip()

st.markdown("---")

if query:
    st.success(f"Menjalankan analisis CTI untuk target: **{query}**")
    st.markdown("")

    # Menu Tab Sesuai Fitur Utama Osint-Pro
    tab_user, tab_domain, tab_pddikti, tab_ip, tab_breach, tab_dork = st.tabs([
        "👤 Identity Recon", 
        "🌐 Subdomain & SSL", 
        "🎓 PDDikti Verification", 
        "🌍 Network & Geolocation", 
        "📧 Breach & Contact", 
        "🔎 Advanced CTI Dorks"
    ])

    # 1. Identity & Social Recon (Live Check)
    with tab_user:
        st.subheader("Verifikasi Identitas & Jejak Media Sosial")
        st.write("Melakukan pengecekan status HTTP langsung pada platform publik utama.")
        
        platforms = {
            "GitHub": f"https://github.com/{query}",
            "Instagram": f"https://www.instagram.com/{query}/",
            "X (Twitter)": f"https://twitter.com/{query}",
            "TikTok": f"https://www.tiktok.com/@{query}",
            "Telegram": f"https://t.me/{query}",
            "LinkedIn": f"https://www.linkedin.com/in/{query}",
            "Reddit": f"https://www.reddit.com/user/{query}"
        }

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        results = []
        for plat, url in platforms.items():
            status = "Netral"
            try:
                resp = requests.get(url, headers=headers, timeout=4, allow_redirects=True)
                status = "🟢 Ditemukan (200)" if resp.status_code == 200 else "🔴 Tidak Ada (404)"
            except:
                status = "🛡️ Terproteksi / Timeout"
            results.append({"Platform": plat, "Status Akun": status, "URL Target": url})
            
        st.dataframe(pd.DataFrame(results), use_container_width=True)

    # 2. Subdomain & Certificate Transparency (crt.sh)
    with tab_domain:
        st.subheader("Certificate Transparency & Subdomain Intelligence")
        clean_domain = query.replace("https://", "").replace("http://", "").split("/")[0]
        st.write(f"Menganalisis riwayat sertifikat SSL publik untuk domain: **{clean_domain}**")
        
        try:
            crt_url = f"https://crt.sh/?q={clean_domain}&output=json"
            response = requests.get(crt_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=8)
            if response.status_code == 200 and response.content:
                data = response.json()
                subdomains = set()
                for entry in data:
                    for sub in entry.get("name_value", "").split("\n"):
                        subdomains.add(sub.strip().lower())
                df_sub = pd.DataFrame(list(subdomains), columns=["Subdomain Unik Teridentifikasi"])
                st.success(f"Ditemukan {len(df_sub)} entri unik!")
                st.dataframe(df_sub, use_container_width=True)
            else:
                st.info("Tidak ada data subdomain terekam.")
                st.markdown(f"👉 [Buka crt.sh manual](https://crt.sh/?q={clean_domain})")
        except Exception as e:
            st.warning(f"Koneksi terbatas: {e}")
            st.markdown(f"👉 [Buka crt.sh manual](https://crt.sh/?q={clean_domain})")

    # 3. PDDikti Public Verification (Khas Osint-Pro)
    with tab_pddikti:
        st.subheader("Verifikasi Data Pendidikan Tinggi (PDDikti)")
        st.write("Mengarahkan pencarian langsung ke database resmi PDDikti untuk validasi latar belakang akademis target.")
        encoded_q = urllib.parse.quote(query)
        pddikti_url = f"https://pddikti.kemdikbud.go.id/search?q={encoded_q}"
        st.markdown(f"Target Nama/Keyword: **{query}**")
        st.markdown(f"👉 **Buka Pencarian PDDikti:** [Klik di sini untuk verifikasi akademis]({pddikti_url})")

    # 4. Network & Geolocation
    with tab_ip:
        st.subheader("Analisis Jaringan & Geolocation IP/Domain")
        clean_ip = query.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            is_ip = all(part.isdigit() for part in clean_ip.split(".") if part) and len(clean_ip.split(".")) == 4
            api_url = f"http://ip-api.com/json/{clean_ip}" if is_ip else f"https://ipapi.co/{clean_ip}/json/"
            res = requests.get(api_url, timeout=7)
            if res.status_code == 200:
                st.json(res.json())
            else:
                st.error("Gagal mengambil data jaringan.")
        except Exception as e:
            st.error(f"Error: {e}")

    # 5. Breach & Contact Recon
    with tab_breach:
        st.subheader("Analisis Kontak, MX Record & Breach Intelligence")
        if "@" in query:
            domain_part = query.split("@")[-1]
            st.markdown(f"- **Domain Email:** `{domain_part}`")
            st.markdown(f"- **MXToolbox DNS Check:** [MXToolbox](https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain_part})")
            st.markdown(f"- **HaveIBeenPwned Check:** [HaveIBeenPwned](https://haveibeenpwned.com/)")
        else:
            clean_phone = query.replace("+", "").replace(" ", "").replace("-", "")
            st.markdown(f"- **WhatsApp Direct Link:** [Buka Chat](https://wa.me/{clean_phone})")
            st.markdown(f"- **Country Code Lookup:** [CountryCode](https://www.countrycode.org/)")

    # 6. Advanced CTI Dorks
    with tab_dork:
        st.subheader("Advanced CTI Google Dorking Engine")
        st.write("Konstruksi dork komprehensif untuk ekstraksi dokumen sensitif dan eksposur aset.")
        
        dorks = {
            "Dokumen Sensitif (PDF/Doc/Xls)": f'site:{query} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:xlsx',
            "Direktori Terbuka / Indeks Server": f'site:{query} intitle:"index of"',
            "File Konfigurasi / Database (.env / .sql / .json)": f'site:{query} filetype:env OR filetype:sql OR filetype:json OR filetype:txt',
            "Penyebutan Profesional / Media Sosial": f'"{query}" site:linkedin.com OR site:instagram.com OR site:twitter.com',
            "Jejak Akademik / PDDikti": f'"{query}" site:pddikti.kemdikbud.go.id OR site:academia.edu'
        }
        
        for title, dork_q in dorks.items():
            search_url = f"https://www.google.com/search?q={urllib.parse.quote(dork_q)}"
            st.markdown(f"**{title}**  \n`{dork_q}`  \n👉 [Buka CTI Google Search]({search_url})")
            st.markdown("---")

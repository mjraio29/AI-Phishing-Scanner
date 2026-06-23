import streamlit as st
from scanner.url_scanner import URLScanner
from scanner.email_scanner import EmailScanner

st.set_page_config(page_title="AI Phishing Scanner", page_icon="🛡️", layout="centered")

st.title("🛡️ AI Phishing Scanner")
st.caption("Dual-layer phishing detection using ML feature engineering + Claude LLM analysis")

use_llm = st.toggle("Use LLM Analysis (Claude)", value=True)

tab1, tab2 = st.tabs(["🔗 Scan URL", "📧 Scan Email"])

with tab1:
    url = st.text_input("Enter a URL to scan", placeholder="https://example.com")
    if st.button("Scan URL", type="primary"):
        if not url:
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Scanning..."):
                try:
                    result = URLScanner(use_llm=use_llm).scan(url)
                    verdict = result["verdict"]
                    score = result["score"]
                    flags = result["flags"]
                    analysis = result.get("llm_analysis", "")

                    if verdict == "PHISHING":
                        st.error(f"🚨 Verdict: **{verdict}**  —  Risk Score: `{score}`")
                    elif verdict == "SUSPICIOUS":
                        st.warning(f"⚠️ Verdict: **{verdict}**  —  Risk Score: `{score}`")
                    else:
                        st.success(f"✅ Verdict: **{verdict}**  —  Risk Score: `{score}`")

                    if flags:
                        st.subheader("🚩 Flags Detected")
                        for f in flags:
                            st.markdown(f"- {f}")

                    if analysis:
                        st.subheader("🤖 LLM Analysis")
                        st.info(analysis)

                except Exception as e:
                    st.error(f"Error: {e}")

with tab2:
    email_text = st.text_area("Paste email content to scan", height=200,
                               placeholder="Paste the full email body here...")
    if st.button("Scan Email", type="primary"):
        if not email_text:
            st.warning("Please paste some email content.")
        else:
            with st.spinner("Scanning..."):
                try:
                    result = EmailScanner(use_llm=use_llm).scan(email_text)
                    verdict = result["verdict"]
                    score = result["score"]
                    flags = result.get("flags", [])
                    analysis = result.get("llm_analysis", "")

                    if verdict == "PHISHING":
                        st.error(f"🚨 Verdict: **{verdict}**  —  Risk Score: `{score}`")
                    elif verdict == "SUSPICIOUS":
                        st.warning(f"⚠️ Verdict: **{verdict}**  —  Risk Score: `{score}`")
                    else:
                        st.success(f"✅ Verdict: **{verdict}**  —  Risk Score: `{score}`")

                    if flags:
                        st.subheader("🚩 Flags Detected")
                        for f in flags:
                            st.markdown(f"- {f}")

                    if analysis:
                        st.subheader("🤖 LLM Analysis")
                        st.info(analysis)

                except Exception as e:
                    st.error(f"Error: {e}")

st.divider()
st.caption("Built by Michael Raio · github.com/mjraio29")

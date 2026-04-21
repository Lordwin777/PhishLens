import streamlit as st
from checker.url_check import scan

st.title("🔍 PhishLens")
st.write("Detect phishing links instantly")

url = st.text_input("Paste a URL to scan")

if st.button("Scan URL"):
    if url:
        result = scan(url)
        if result['verdict'] == 'SAFE':
            st.success(f"✅ SAFE — {result['reason']}")
        elif 'PHISHING' in result['verdict']:
            st.error(f"🚨 {result['verdict']} — {result['reason']}")
        else:
            st.warning(f"⚠️ {result['verdict']} — {result['reason']}")

        st.metric("Phishing Confidence", f"{result['confidence']}%")

        if result['blacklist_hit']:
            st.error("⚠️ Found in phishing database!")

        st.subheader("Feature Breakdown")
        for feature, score in result['details'].items():
            if score == 1:
                st.write(f"✅ {feature.replace('_', ' ')}")
            elif score == 0:
                st.write(f"⚠️ {feature.replace('_', ' ')}")
            else:
                st.write(f"🚨 {feature.replace('_', ' ')}")
    else:
        st.warning("Please enter a URL")
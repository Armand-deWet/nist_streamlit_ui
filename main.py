import streamlit as st
import pandas as pd
import requests
import zipfile
from PIL import Image
import base64
from io import BytesIO

# Custom CSS using colors from the palette
# st.markdown("""
#     <style>
#     body {
#         background-color: #BEC9CD;
#         color: #1C1C1C;
#     }

#     .block-container {
#         padding: 2rem;
#         background-color: #FFFFFF;
#         border-radius: 10px;
#     }

#     h1, h2, h3, h4, h5, h6, p, li {
#         color: #1C1C1C;
#     }

#     .stButton>button {
#         background-color: #147C9B;
#         color: white;
#         border: none;
#         border-radius: 8px;
#         padding: 0.5rem 1rem;
#         font-weight: bold;
#     }

#     .stButton>button:hover {
#         background-color: #216882;
#         color: white;
#     }

#     /* Selectbox */
#     [data-testid="stSelectbox"] {
#         background-color: #71BCCD;
#         color: #1C1C1C;
#         border-radius: 8px;
#     }

#     /* Input box */
#     input {
#         background-color: #FFFFFF !important;
#         color: #1C1C1C !important;
#     }

#     /* Sliders */
#     [data-testid="stSlider"] > div {
#         background-color: #147C9B !important;
#     }

#     .custom-box {
#         background-color: #71BCCD;
#         padding: 20px;
#         border-radius: 12px;
#         margin-bottom: 20px;
#         box-shadow: 0 4px 6px rgba(0,0,0,0.1);
#     }
            
#     html, body {
#     background-color: #000000 !important;  /* Entire page background */
#     color: #FFFFFF;
#     }

#     /* Also target the main app container */
#     section.main {
#         background-color: #000000 !important;
#     }

#     /* Optional: make the content container dark to match */
#     .block-container {
#         background-color: #1A1A1A !important;  /* Dark inner container */
#         color: #FFFFFF;
#     }
#     </style>
# """, unsafe_allow_html=True)

st.markdown("""
    <style>
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #000000 !important;
        color: #FFFFFF !important;
    }

    section.main {
        background-color: #000000 !important;
    }

    .block-container {
        background-color: #1A1A1A !important;
        border-radius: 10px;
        padding: 2rem;
    }

    h1, h2, h3, h4, h5, h6, p, li, span, div {
        color: #FFFFFF !important;
    }

    .stButton>button {
        background-color: #333333;
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: bold;
    }

    .stButton>button:hover {
        background-color: #555555;
        color: white;
    }

    [data-testid="stSelectbox"] {
        background-color: #333333 !important;
        color: white !important;
        border-radius: 8px;
    }

    input {
        background-color: #222222 !important;
        color: white !important;
    }

    [data-testid="stSlider"] > div {
        background-color: #333333 !important;
    }

    .custom-box {
        background-color: #222222 !important;
        padding: 20px;
        border-radius: 12px;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px rgba(255,255,255,0.1);
    }

    table {
        background-color: #1A1A1A !important;
        color: #FFFFFF !important;
    }

    th, td {
        border: 1px solid #444 !important;
        padding: 10px !important;
    }
            
    /* JSON display theme fix */
    /* Override JSON display container */
    [data-testid="stJson"] {
        background-color: transparent !important;
        padding: 0 !important;
        margin: 0 !important;
        box-shadow: none !important;
    }

    /* Remove light card background around JSON block */
    [data-testid="stJson"] > div {
        background-color: transparent !important;
        padding: 0 !important;
        margin: 0 !important;
    }

    /* Set dark background for JSON content */
    [data-testid="stJson"] pre {
        background-color: #000000 !important;
        color: #FFFFFF !important;
        border: none !important;
        padding: 1rem !important;
        margin: 0 !important;
        overflow: auto;
        font-size: 14px;
    }

    /* Optional: style JSON keys and values for clarity */
    [data-testid="stJson"] span {
        color: #CCCCCC !important; /* light gray for keys and structure */
    }

    [data-testid="stJson"] span.str {
        color: #00FF00 !important; /* green for strings */
    }

    [data-testid="stJson"] span.num {
        color: #FFD700 !important; /* gold for numbers */
    }

    [data-testid="stJson"] span.bool {
        color: #FF69B4 !important; /* pink for booleans */
    }

    </style>
""", unsafe_allow_html=True)


# Load logo
img = Image.open("ThreatInSight Logo - Color (002).png")
buffered = BytesIO()
img.save(buffered, format="PNG")
img_b64 = base64.b64encode(buffered.getvalue()).decode()

# Inject centered logo with HTML
st.markdown(f"""
    <div style="display: flex; justify-content: center; align-items: center; padding: 1rem;">
        <img src="data:image/png;base64,{img_b64}" width="350"/>
    </div>
""", unsafe_allow_html=True)



cpe_df = pd.read_csv('utils/cpe_df_csv_zip.zip', compression='zip')
product_titles = cpe_df['title'].unique()

headers = {
    'apiKey': '66da31c6-72f6-4f70-8e79-11e1976582c0'
}

def get_vulnerabilities(cpeName):

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="+cpeName
    
    response = requests.get(url, headers=headers)
    res = response.json()
    vulnerabilities = res['vulnerabilities']

    if not vulnerabilities:
        return

    return vulnerabilities

def format_cve_data(res):
    cve_dict = {}
    cve_metrics_dict = {}

    for i in res:
        interim_dict = {}
        id = i['cve']['id']
        published = i['cve']['published']
        last_modified = i['cve']['lastModified']
        v_status = i['cve']['vulnStatus']
        descriptions = [j['lang'] for j in i['cve']['descriptions']]
        desc = i['cve']['descriptions'][descriptions.index('en')]['value']
        references = [r['url'] for r in i['cve']['references']]
        try:
            metrics = i['cve']['metrics']
        except:
            metrics = ''

        interim_dict['published'] = published
        interim_dict['last modified'] = last_modified
        interim_dict['vulnerability status'] = v_status
        interim_dict['description'] = desc
        interim_dict['references'] = references

        cve_dict[id] = interim_dict
        if metrics:
            cve_metrics_dict[id] = metrics

    return cve_dict, cve_metrics_dict


        

st.title('Product Vulnerability Search Tool')

query = st.text_input("Search for a product:")

if query:
    matches = [i for i in product_titles if query.lower() in i.lower()]
    if matches:
        selected = st.selectbox("Select from matches:", matches[:100])
        st.write("You selected:", selected)

        st.divider()

        cpeName = cpe_df.loc[cpe_df['title'] == selected, 'cpeName'].values

        if len(cpeName) > 1:
            name = st.selectbox("Please select 1 to use as search criteria:", cpeName)

        else:
            name = cpeName[0]

        st.write("The corresponding cpeName(s) are as follow:", name)
        st.write("This search term will be used to find all known vulnerabilities associated with the product")

        st.divider()

        v_res = get_vulnerabilities(name)
        if not v_res:
            st.write('No vulnerabilities found')
        else:
            cve_dict, cve_metrics_dict = format_cve_data(v_res)
            selected_cve_id = st.selectbox("Select vulnerability id:", list(cve_dict.keys()))

            st.header('Vulnerability parameters')
            st.write('Published: ',  cve_dict[selected_cve_id]['published'])
            st.write('Last modified date: ',  cve_dict[selected_cve_id]['last modified'])
            st.write('Vulnerability status: ',  cve_dict[selected_cve_id]['vulnerability status'])
            st.write('Description: ',  cve_dict[selected_cve_id]['description'])
            st.write('References: ',  cve_dict[selected_cve_id]['references'])

            st.divider()
            if not cve_metrics_dict:
                st.write("No metrics available")
            else:
                if len(cve_metrics_dict[selected_cve_id].keys()) > 1:
                    selected_metric = st.selectbox("Select a metric to view:", list(cve_metrics_dict[selected_cve_id].keys()))
                else: 
                    selected_metric = list(cve_metrics_dict[selected_cve_id].keys())[0]

                st.write('Vulnerability metric name: ', selected_metric)

                st.header('Vulnerability Metric', selected_metric)
                if 'V2' in selected_metric:
                    summary_data = [{
                        'baseScore': cve_metrics_dict[selected_cve_id][selected_metric][0]['cvssData']['baseScore'],
                        'baseSeverity': cve_metrics_dict[selected_cve_id][selected_metric][0]['baseSeverity'],
                        'exploitabilityScore': cve_metrics_dict[selected_cve_id][selected_metric][0]['exploitabilityScore'],
                        'impactScore': cve_metrics_dict[selected_cve_id][selected_metric][0]['impactScore']
                    }]

                    table_html = """
                    <table style="width:100%; border-collapse: collapse; text-align: center; background-color: #FFFFFF;">
                        <tr style="background-color: #71BCCD; color: white;">
                            {} 
                        </tr>
                        <tr>
                            {} 
                        </tr>
                    </table>
                    """.format(
                        ''.join([f"<th style='border: 1px solid #BEC9CD; padding: 10px;'>{k}</th>" for k in summary_data[0].keys()]),
                        ''.join([f"<td style='border: 1px solid #BEC9CD; padding: 10px; color: white;'>{v}</td>" for v in summary_data[0].values()])
                    )

                    st.subheader(f"{selected_metric} Summary Table")
                    st.markdown(table_html, unsafe_allow_html=True)

                elif 'V3' in selected_metric:
                    summary_data = [{
                        'baseScore': cve_metrics_dict[selected_cve_id][selected_metric][0]['cvssData']['baseScore'],
                        'baseSeverity': cve_metrics_dict[selected_cve_id][selected_metric][0]['cvssData']['baseSeverity'],
                        'exploitabilityScore': cve_metrics_dict[selected_cve_id][selected_metric][0]['exploitabilityScore'],
                        'impactScore': cve_metrics_dict[selected_cve_id][selected_metric][0]['impactScore']
                    }]

                    table_html = """
                    <table style="width:100%; border-collapse: collapse; text-align: center; background-color: #1A1A1A;">
                        <tr style="background-color: #71BCCD; color: white;">
                            {} 
                        </tr>
                        <tr>
                            {} 
                        </tr>
                    </table>
                    """.format(
                        ''.join([f"<th style='border: 1px solid #BEC9CD; padding: 10px;'>{k}</th>" for k in summary_data[0].keys()]),
                        ''.join([f"<td style='border: 1px solid #444; padding: 10px; color: #FFFFFF;'>{v}</td>" for v in summary_data[0].values()])
                    )

                    st.subheader(f"{selected_metric} Summary Table")
                    st.markdown(table_html, unsafe_allow_html=True)
                
                st.subheader("Complete Information")
                st.json(cve_metrics_dict[selected_cve_id][selected_metric])
    else:
         st.write("No product matches your search string. Please search for a different product title...")        


else:
    st.info("Type something to begin searching.")



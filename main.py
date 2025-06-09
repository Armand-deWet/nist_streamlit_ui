import streamlit as st
import pandas as pd
import requests
import zipfile

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

                # metric = cve_metrics_dict[selected_cve_id][selected_metric][0]
                st.header('Vulnerability Metric', selected_metric)
                # st.table(metric['cvssData'])

                st.json(cve_metrics_dict[selected_cve_id][selected_metric])
    else:
         st.write("No product mach your search string. Please search for a different product title")        


else:
    st.info("Type something to begin searching.")

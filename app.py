import io
from datetime import datetime
import numpy as np
import pandas as pd
import streamlit as st

st.set_page_config(page_title="SIEM EPS & GPD Estimator", layout="wide")

# ---------- Defaults ----------
DEFAULT_MAPPING = pd.DataFrame([
    {"make": "Fortinet", "model": "FortiGate 100", "category": "firewall_medium"},
    {"make": "Fortinet", "model": "FortiGate 300", "category": "firewall_large"},
    {"make": "Palo Alto", "model": "PA-3220", "category": "firewall_medium"},
    {"make": "Palo Alto", "model": "PA-5250", "category": "firewall_large"},
    {"make": "Cisco", "model": "ASA 5506", "category": "firewall_small"},
    {"make": "Windows", "model": "Server", "category": "server_windows"},
    {"make": "Linux", "model": "Server", "category": "server_linux"},
    {"make": "Microsoft", "model": "Office 365", "category": "saas_o365"},
    {"make": "AWS", "model": "CloudTrail", "category": "cloud_aws_ct"},
    {"make": "Azure", "model": "Activity", "category": "cloud_azure_activity"},
    {"make": "Okta", "model": "SSO", "category": "idm_okta"},
    {"make": "Cisco", "model": "AnyConnect", "category": "vpn_remote"},
    {"make": "CrowdStrike", "model": "Falcon", "category": "edr_cs"},
])

CATEGORY_ASSUMPTIONS = pd.DataFrame([
    {"category": "firewall_small",  "label": "Firewall: Small",  "eps_per_device": 30,  "event_size_bytes": 500},
    {"category": "firewall_medium", "label": "Firewall: Medium", "eps_per_device": 100, "event_size_bytes": 500},
    {"category": "firewall_large",  "label": "Firewall: Large",  "eps_per_device": 250, "event_size_bytes": 500},
    {"category": "server_windows",  "label": "Server: Windows",  "eps_per_device": 5,   "event_size_bytes": 350},
    {"category": "server_linux",    "label": "Server: Linux",    "eps_per_device": 3,   "event_size_bytes": 300},
    {"category": "saas_o365",       "label": "SaaS: Microsoft 365 (per 100 users)", "eps_per_device": 20, "event_size_bytes": 600},
    {"category": "cloud_aws_ct",    "label": "Cloud: AWS CloudTrail (per account)", "eps_per_device": 15, "event_size_bytes": 750},
    {"category": "cloud_azure_activity", "label": "Cloud: Azure Activity (per subscription)", "eps_per_device": 12, "event_size_bytes": 700},
    {"category": "idm_okta",        "label": "Identity: Okta (per 1k users)", "eps_per_device": 8, "event_size_bytes": 650},
    {"category": "vpn_remote",      "label": "VPN: Remote Access (per 1k users)", "eps_per_device": 10, "event_size_bytes": 400},
    {"category": "edr_cs",          "label": "EDR: CrowdStrike (per 1k endpoints)", "eps_per_device": 20, "event_size_bytes": 450},
])

CATEGORY_LOOKUP = {row["category"]: row for _, row in CATEGORY_ASSUMPTIONS.iterrows()}

# ---------- Sidebar ----------
with st.sidebar:
    st.header("Templates & Settings")

    map_file = st.file_uploader("Mapping CSV (make,model,category)", type=["csv"])
    if map_file is not None:
        try:
            user_map = pd.read_csv(map_file)
            user_map.columns = [c.strip().lower() for c in user_map.columns]
            if {"make", "model", "category"}.issubset(user_map.columns):
                DEFAULT_MAPPING = user_map
                st.success(f"Loaded {len(DEFAULT_MAPPING)} mapping rows.")
            else:
                st.error("Mapping CSV must include: make, model, category")
        except Exception as e:
            st.error(f"Failed to read mapping: {e}")

    cat_file = st.file_uploader("Category assumptions CSV", type=["csv"])
    if cat_file is not None:
        try:
            cat_df = pd.read_csv(cat_file)
            cat_df.columns = [c.strip().lower() for c in cat_df.columns]
            if {"category", "label", "eps_per_device", "event_size_bytes"}.issubset(cat_df.columns):
                CATEGORY_ASSUMPTIONS = cat_df
                CATEGORY_LOOKUP = {row["category"]: row for _, row in CATEGORY_ASSUMPTIONS.iterrows()}
                st.success(f"Loaded {len(CATEGORY_ASSUMPTIONS)} category rows.")
            else:
                st.error("Category CSV must include: category,label,eps_per_device,event_size_bytes")
        except Exception as e:
            st.error(f"Failed to read categories: {e}")

    st.divider()
    st.subheader("Sizing knobs")
    peak_factor = st.number_input("Peak factor (x avg EPS)", min_value=1.0, value=3.0, step=0.1)
    headroom_pct = st.number_input("Headroom %", min_value=0.0, value=20.0, step=1.0)
    compression_pct = st.number_input("Compression % (stored/raw)", min_value=1.0, max_value=100.0, value=35.0, step=1.0)
    schema_overhead_pct = st.number_input("Normalization overhead %", min_value=0.0, max_value=200.0, value=10.0, step=1.0)

    st.divider()
    st.download_button(
        "Download mapping template CSV",
        data=DEFAULT_MAPPING.to_csv(index=False).encode("utf-8"),
        file_name="mapping_template.csv",
        mime="text/csv",
    )
    st.download_button(
        "Download category assumptions CSV",
        data=CATEGORY_ASSUMPTIONS.to_csv(index=False).encode("utf-8"),
        file_name="category_assumptions.csv",
        mime="text/csv",
    )

# ---------- Main ----------
st.title("SIEM EPS & GPD Estimator")
st.caption("Estimate average/peak EPS and storage (GB/day) from your inventory. Adjust assumptions in the sidebar.")

st.subheader("1) Asset inventory")
st.write("Upload a CSV (make,model,quantity) or edit inline.")

inv_file = st.file_uploader("Inventory CSV (make,model,quantity)", type=["csv"], key="inv")

DEFAULT_INVENTORY = pd.DataFrame([
    {"make": "Fortinet", "model": "FortiGate 100", "quantity": 2},
    {"make": "Palo Alto", "model": "PA-3220", "quantity": 1},
    {"make": "Windows", "model": "Server", "quantity": 80},
    {"make": "Linux", "model": "Server", "quantity": 40},
    {"make": "Microsoft", "model": "Office 365", "quantity": 2},  # 2x blocks (per 100 users) -> 200 users
    {"make": "AWS", "model": "CloudTrail", "quantity": 1},
    {"make": "Okta", "model": "SSO", "quantity": 1},
])

if inv_file is not None:
    try:
        inventory_df = pd.read_csv(inv_file)
        inventory_df.columns = [c.strip().lower() for c in inventory_df.columns]
        if not {"make", "model", "quantity"}.issubset(inventory_df.columns):
            st.error("Inventory CSV must include: make, model, quantity")
            inventory_df = DEFAULT_INVENTORY.copy()
    except Exception as e:
        st.error(f"Failed to read inventory: {e}")
        inventory_df = DEFAULT_INVENTORY.copy()
else:
    inventory_df = DEFAULT_INVENTORY.copy()

edited_inv = st.data_editor(
    inventory_df,
    num_rows="dynamic",
    use_container_width=True,
    key="inv_editor",
)

# ---------- 2) Map to categories ----------
st.subheader("2) Map to categories")
st.write("We try to auto-map make+model to a category. Confirm or override as needed.")

_map = DEFAULT_MAPPING.copy()
_map["make_lc"] = _map["make"].str.lower()
_map["model_lc"] = _map["model"].str.lower()

rows = []
for _, r in edited_inv.iterrows():
    make = str(r.get("make", "")).strip()
    model = str(r.get("model", "")).strip()
    qty = int(r.get("quantity", 0) or 0)
    candidates = _map[_map["make_lc"] == make.lower()]
    hit = candidates[candidates["model_lc"].apply(lambda x: x in model.lower() or model.lower() in x)]
    category_guess = hit["category"].iloc[0] if len(hit) else None
    rows.append({"make": make, "model": model, "quantity": qty, "category": category_guess or ""})

mapped_df = pd.DataFrame(rows)

category_options = CATEGORY_ASSUMPTIONS[["category", "label"]].copy()
category_dict = dict(zip(category_options["category"], category_options["label"]))

out_rows = []
for i, r in mapped_df.iterrows():
    col1, col2, col3, col4 = st.columns([2, 2, 1, 2])
    with col1:
        st.text_input("Make", value=r["make"], key=f"make_{i}")
    with col2:
        st.text_input("Model", value=r["model"], key=f"model_{i}")
    with col3:
        st.number_input("Qty", min_value=0, value=int(r["quantity"]), key=f"qty_{i}")
    with col4:
        selected = st.selectbox(
            "Category",
            options=[""] + list(category_dict.keys()),
            index=(1 + list(category_dict.keys()).index(r["category"])) if r["category"] in category_dict else 0,
            format_func=lambda x: category_dict.get(x, "-- choose --") if x else "-- choose --",
            key=f"cat_{i}",
        )
    out_rows.append({
        "make": st.session_state[f"make_{i}"],
        "model": st.session_state[f"model_{i}"],
        "quantity": st.session_state[f"qty_{i}"],
        "category": st.session_state[f"cat_{i}"] or None,
    })

confirmed_df = pd.DataFrame(out_rows)

# ---------- 3) Assumptions editor ----------
st.subheader("3) Assumptions (per category)")
st.write("Tune EPS/device and event size. Values below are averages; peak is applied separately.")
assump_editor = st.data_editor(CATEGORY_ASSUMPTIONS, use_container_width=True, key="assump_editor")
CATEGORY_LOOKUP = {row["category"]: row for _, row in assump_editor.iterrows()}

# ---------- 4) Results ----------
st.subheader("4) Results")

calc_rows = []
for _, r in confirmed_df.dropna(subset=["category"]).iterrows():
    cat = r["category"]
    qty = int(r["quantity"]) if pd.notna(r["quantity"]) else 0
    if qty <= 0 or cat not in CATEGORY_LOOKUP:
        continue

    eps_per_device = float(CATEGORY_LOOKUP[cat]["eps_per_device"]) or 0.0
    event_size = float(CATEGORY_LOOKUP[cat]["event_size_bytes"]) or 0.0

    avg_eps = qty * eps_per_device
    peak_eps = avg_eps * peak_factor

    events_per_day = avg_eps * 86400
    raw_bytes_per_day = events_per_day * event_size
    stored_bytes_per_day = raw_bytes_per_day * (1.0 + schema_overhead_pct / 100.0) * (compression_pct / 100.0)

    calc_rows.append({
        "make": r["make"],
        "model": r["model"],
        "category": cat,
        "label": CATEGORY_LOOKUP[cat]["label"],
        "quantity": qty,
        "avg_eps": avg_eps,
        "peak_eps": peak_eps,
        "events_per_day": events_per_day,
        "stored_gb_per_day": stored_bytes_per_day / (1024 ** 3),
    })

calc_df = pd.DataFrame(calc_rows)

if calc_df.empty:
    st.info("Add at least one mapped row with quantity > 0 to see results.")
else:
    total_avg_eps = calc_df["avg_eps"].sum()
    total_peak_eps = calc_df["peak_eps"].sum()
    total_gb_per_day = calc_df["stored_gb_per_day"].sum()

    cap_avg_eps = total_avg_eps * (1 + headroom_pct / 100.0)
    cap_peak_eps = total_peak_eps * (1 + headroom_pct / 100.0)

    st.metric("Total Avg EPS", f"{total_avg_eps:,.0f}")
    st.metric("Total Peak EPS", f"{total_peak_eps:,.0f}")
    st.metric("Storage (GB/day)", f"{total_gb_per_day:,.2f}")
    st.caption(f"Capacity targets with {headroom_pct:.0f}% headroom -> Avg: {cap_avg_eps:,.0f} EPS | Peak: {cap_peak_eps:,.0f} EPS")

    st.dataframe(
        calc_df[["make", "model", "label", "quantity", "avg_eps", "peak_eps", "stored_gb_per_day"]]
        .sort_values(["label", "avg_eps"], ascending=[True, False])
        .rename(columns={"label": "Category", "stored_gb_per_day": "GB/day"}),
        use_container_width=True,
    )

    # Downloads
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    def _to_bytesio_csv(df):
        bio = io.BytesIO()
        bio.write(df.to_csv(index=False).encode("utf-8"))
        bio.seek(0)
        return bio

    def _to_bytesio_xlsx(df_dict):
        bio = io.BytesIO()
        # Requires: pip install openpyxl
        with pd.ExcelWriter(bio, engine="openpyxl") as xw:
            for name, df in df_dict.items():
                df.to_excel(xw, sheet_name=name[:31], index=False)
        bio.seek(0)
        return bio

    st.download_button(
        label="Download results (CSV)",
        data=_to_bytesio_csv(calc_df),
        file_name=f"siem_sizing_results_{ts}.csv",
        mime="text/csv",
    )

    st.download_button(
        label="Download workbook (Excel)",
        data=_to_bytesio_xlsx({
            "Inventory": confirmed_df,
            "Assumptions": assump_editor,
            "Results": calc_df,
        }),
        file_name=f"siem_sizing_{ts}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

# ---------- 5) Save updated mapping ----------
st.subheader("5) Save your updated mapping")
st.write("If you updated categories above, you can export the consolidated mapping for next time.")

export_map = confirmed_df.dropna(subset=["category"]).copy()
export_map = export_map[["make", "model", "category"]].drop_duplicates().sort_values(["make", "model"])

if export_map.empty:
    st.caption("Nothing to export yet.")
else:
    st.download_button(
        "Download updated mapping CSV",
        data=export_map.to_csv(index=False).encode("utf-8"),
        file_name="siem_mapping_updated.csv",
        mime="text/csv",
    )

st.divider()
st.caption("Estimates only. Validate with vendor docs, telemetry samples, and pilot ingestion.")

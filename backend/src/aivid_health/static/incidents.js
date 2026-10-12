"use strict";
let incidentTab = "open", incidentOffset = 0, incidentRequest = 0;
let incidentFilter = {node:"", severity:"", q:""};
const expandedIncidents = new Set();
const lifecycleName = kind => ({open:"Raised", escalated:"Escalated", recovered:"Recovered", test:"Test email"}[kind] || kind);
const deliveryBadge = status => status === "cancelled" ? '<span class="status cancelled">dismissed</span>' : status ? badge(status) : '<span class="muted">No retained email</span>';
const incidentBadge = status => `<span class="status incident-${esc(status)}">${esc({open:"Open", closed:"Closed", unknown:"History incomplete"}[status] || status)}</span>`;
function elapsed(seconds) {
    if (seconds == null) return "Unknown";
    seconds = Math.max(0, Math.floor(seconds));
    const d = Math.floor(seconds / 86400), h = Math.floor(seconds % 86400 / 3600), m = Math.floor(seconds % 3600 / 60);
    return d ? `${d}d ${h}h ${m}m` : h ? `${h}h ${m}m` : m ? `${m}m ${seconds % 60}s` : `${seconds}s`;
}
function observation(row) {
    if (row.value == null) return "Value unavailable";
    const base = row.metric.split(":")[0];
    if (base === "availability") return row.value ? "Server unreachable" : "Server reachable";
    if (base === "sensor_error") return row.value ? "Sensor unavailable" : "Sensor available";
    return Number(row.value).toFixed(1) + (base === "gpu_temperature" ? " °C" : "%");
}
function chooseIncidentTab(tab) {
    incidentTab = tab; incidentOffset = 0; expandedIncidents.clear();
    if ($("incident-results")) $("incident-results").innerHTML = "";
    renderAlerts();
}
function viewOpenIncidents() {
    incidentTab = "open"; incidentOffset = 0;
    incidentFilter = {node:"", severity:"", q:""};
    $("alerts-page").innerHTML = ""; openPage("alerts");
}
function incidentTableRow(row) {
    const open = row.status === "open", closed = row.status === "closed", expanded = expandedIncidents.has(row.id);
    return `<tr class="incident-row"><td><strong>${esc(row.label)}</strong>${row.resource ? `<span class="resource-id" title="${esc(row.resource)}">${esc(row.resource)}</span>` : ""}<button class="text-button incident-expand" data-incident="${esc(row.id)}" aria-expanded="${expanded}">${expanded ? "Hide" : "View"} details ${expanded ? "−" : "+"}</button></td>
        <td><strong>${esc(row.node_name)}</strong></td><td>${incidentBadge(row.status)}<p class="small muted">${open ? "Awaiting confirmed recovery" : closed ? "Recovery confirmed" : "Recovery not recorded"}</p></td>
        <td>${badge(row.severity)}${closed ? '<p class="small muted">Peak severity</p>' : ""}</td>
        <td class="incident-times"><span>Raised <strong>${row.opened_at ? when(row.opened_at) : "Not retained"}</strong></span>${closed ? `<span>Recovered <strong>${when(row.resolved_at)}</strong></span>` : ""}<span>${open ? "Open for" : "Duration"} <strong>${elapsed(row.duration_seconds)}</strong></span></td>
        <td>${deliveryBadge(row.latest_delivery)}${row.delivery_pending ? `<p class="small muted">${row.delivery_pending} awaiting delivery / review</p>` : ""}</td></tr>
        ${expanded ? `<tr class="incident-detail"><td colspan="6"><div class="incident-detail-head"><strong>${open ? "Last evaluated value" : "Last recorded value"}: ${esc(observation(row))}</strong>${open ? `<span class="small muted">Last check: ${when(row.last_observed)}</span>` : ""}</div>${row.history_partial ? '<p class="form-note">Some earlier history is no longer available. Times are shown only where retained.</p>' : ""}<p class="small">${esc(row.detail || "No notification detail retained.")}</p><ol class="incident-timeline">${row.timeline.map(e=>`<li><div><strong>${esc(lifecycleName(e.kind))}</strong><span class="muted">${when(e.created_at)}</span>${deliveryBadge(e.status)}</div><p>${esc(e.detail)}</p><p class="muted">${esc(e.detail_delivery)} · Sender: ${esc(e.sender_name || "Pending")}</p></li>`).join("") || '<li>No retained notification history.</li>'}</ol></td></tr>` : ""}`;
}
function deliveryTableRow(e) {
    return `<tr><td>${when(e.created_at)}<p class="small muted">${esc(e.node_name)}</p></td><td><strong>${esc(lifecycleName(e.kind))} · ${esc(e.label)}</strong>${e.resource ? `<span class="resource-id">${esc(e.resource)}</span>` : ""}<p class="small muted">${esc(e.detail)}</p></td><td>${badge(e.severity)}</td><td>${deliveryBadge(e.status)}<p class="small muted">${esc(e.detail_delivery)}<br>Attempts ${e.attempts} · Sender ${esc(e.sender_name || "Pending")}</p>${state.is_leader && ["uncertain","retry","pending"].includes(e.status) ? `<button class="secondary dismiss-email" data-id="${esc(e.id)}">Dismiss notification</button>` : ""}</td></tr>`;
}
function updateIncidentCounts(summary, deliveries) {
    for (const key of ["open", "closed", "all"]) {
        const el = $("incident-count-" + key); if (el) el.textContent = summary[key];
    }
    $("incident-count-delivery").textContent = deliveries.total;
    $("incident-open-total").textContent = summary.open;
    $("incident-open-note").textContent = `${summary.critical} critical · ${summary.warning} warning`;
    $("incident-closed-total").textContent = summary.closed;
    $("incident-delivery-total").textContent = deliveries.pending;
    $("incident-incomplete").textContent = summary.unknown ? `${summary.unknown} older incident${summary.unknown === 1 ? " has" : "s have"} incomplete history. Find ${summary.unknown === 1 ? "it" : "them"} under All incidents.` : "";
}
function renderAlerts() {
    if (!$("incident-tabs")) {
        $("alerts-page").innerHTML = `<div class="page-heading"><div><h1>Incidents</h1><p>Track unresolved issues and confirmed recoveries across your servers.</p></div><span class="tag">SHARED INCIDENT HISTORY</span></div>
            <div class="incident-summary"><button class="stat" data-category="open"><span class="stat-label">Open · needs attention</span><span id="incident-open-total" class="stat-value">—</span><span id="incident-open-note" class="stat-note"></span></button><button class="stat" data-category="closed"><span class="stat-label">Closed · recovered</span><span id="incident-closed-total" class="stat-value">—</span><span class="stat-note">Confirmed recoveries · last 90 days</span></button><button class="stat" data-category="delivery"><span class="stat-label">Emails awaiting delivery / review</span><span id="incident-delivery-total" class="stat-value">—</span><span class="stat-note">Email status is tracked separately</span></button></div>
            <p id="incident-freshness" class="form-note"></p><section class="panel incident-panel"><div id="incident-tabs" class="incident-tabs" role="group" aria-label="Incident category">${[["open","Open"],["closed","Closed / recovered"],["all","All incidents"],["delivery","Email delivery"]].map(([key,label])=>`<button class="incident-tab" data-category="${key}" aria-pressed="false">${label}<span id="incident-count-${key}">0</span></button>`).join("")}</div>
            <form id="incident-filters" class="incident-filters"><label>Server<select id="incident-node"><option value="">All servers</option>${state.nodes.map(n=>`<option value="${esc(n.id)}" ${incidentFilter.node === n.id ? "selected" : ""}>${esc(n.name)}</option>`).join("")}</select></label><label>Severity<select id="incident-severity">${[["","All severities"],["critical","Critical"],["warning","Warning"],["info","Info"],["unknown","Unknown"]].map(([v,t])=>`<option value="${v}" ${incidentFilter.severity === v ? "selected" : ""}>${t}</option>`).join("")}</select></label><label class="incident-search">Search<input id="incident-search" maxlength="200" type="search" placeholder="Server, resource or detail" value="${esc(incidentFilter.q)}"></label><button class="secondary" type="submit">Apply filters</button><button id="incident-reset" class="text-button" type="button">Clear</button></form>
            <p id="incident-category-note" class="form-note"></p><p id="incident-incomplete" class="small muted"></p><p id="incident-list-status" class="small muted" role="status" aria-live="polite"></p><div class="table-scroll" id="incident-results"></div><div id="incident-pagination" class="incident-pagination"></div></section>`;
        $("alerts-page").querySelectorAll("[data-category]").forEach(b=>b.addEventListener("click",()=>chooseIncidentTab(b.dataset.category)));
        $("incident-filters").addEventListener("submit",e=>{e.preventDefault();incidentFilter={node:$("incident-node").value,severity:$("incident-severity").value,q:$("incident-search").value};incidentOffset=0;expandedIncidents.clear();loadIncidentRows();});
        $("incident-reset").addEventListener("click",()=>{incidentFilter={node:"",severity:"",q:""};$("incident-node").value="";$("incident-severity").value="";$("incident-search").value="";incidentOffset=0;loadIncidentRows();});
    }
    const serverSelect = $("incident-node"), directory = JSON.stringify(state.nodes.map(n=>[n.id,n.name]));
    if (serverSelect.dataset.directory !== directory) {
        const selected = serverSelect.value || incidentFilter.node;
        serverSelect.innerHTML = '<option value="">All servers</option>' + state.nodes.map(n=>`<option value="${esc(n.id)}">${esc(n.name)}</option>`).join("");
        serverSelect.value = selected; serverSelect.dataset.directory = directory;
    }
    $("alerts-page").querySelectorAll(".incident-tab").forEach(b=>{b.classList.toggle("active",b.dataset.category===incidentTab);b.setAttribute("aria-pressed",String(b.dataset.category===incidentTab));});
    updateIncidentCounts(state.incident_summary, state.delivery_summary);
    $("incident-freshness").textContent = !state.leader || state.error ? "Showing the last recorded incident state. Live evaluation needs a communicating majority and a healthy alert sender." : "Open incidents close automatically after confirmed recovery. A sent or dismissed email does not close an incident. Missing readings do not count as recovery.";
    $("incident-category-note").textContent = incidentTab === "delivery" ? "This is the notification log, including test emails. For uncertain delivery, check the recipient mailbox before dismissing the notification. Automatic retries are paused for uncertain delivery." : incidentTab === "open" ? "These issues are still open. The last evaluated value and notification timeline are available under View details." : incidentTab === "closed" ? "These issues have recovered. Severity shows the highest level reached during each incident." : "Each row is one incident. A recurrence after recovery creates a separate incident.";
    loadIncidentRows();
}
async function loadIncidentRows() {
    const request = ++incidentRequest, tab = incidentTab;
    $("incident-list-status").textContent = "Updating…";
    const params = new URLSearchParams({...incidentFilter,offset:incidentOffset,limit:25});
    if (tab !== "delivery") params.set("status",tab);
    try {
        const data = await api((tab === "delivery" ? "/api/deliveries?" : "/api/incidents?") + params);
        if (request !== incidentRequest || page !== "alerts") return;
        incidentOffset = data.offset;
        if (tab !== "delivery") {
            state.incident_summary = data.summary; state.active_incidents = data.summary.open;
            $("alert-count").textContent = data.summary.open;
        } else state.delivery_summary = data.summary;
        updateIncidentCounts(state.incident_summary,state.delivery_summary);
        const columns = tab === "delivery" ? "<th>Time and server</th><th>Notification</th><th>Severity</th><th>Email delivery</th>" : "<th>Incident</th><th>Server</th><th>Incident status</th><th>Severity</th><th>Times and duration</th><th>Latest email</th>";
        const filtered = Object.values(incidentFilter).some(Boolean);
        const empty = filtered ? "No records match these filters." : tab === "open" ? "No open incidents in the current record." : tab === "closed" ? "No confirmed recoveries recorded in the last 90 days." : "No records yet.";
        $("incident-results").innerHTML = `<table class="incident-table"><thead><tr>${columns}</tr></thead><tbody>${data.items.map(tab === "delivery" ? deliveryTableRow : incidentTableRow).join("") || `<tr><td colspan="${tab === "delivery" ? 4 : 6}"><div class="empty">${empty}</div></td></tr>`}</tbody></table>`;
        $("incident-list-status").textContent = data.total ? `Showing ${data.offset+1}–${Math.min(data.offset+data.limit,data.total)} of ${data.total}${filtered ? " matching records" : " records"}` : "0 records";
        $("incident-pagination").innerHTML = data.total > data.limit ? `<button class="secondary" id="incident-prev" ${data.offset === 0 ? "disabled" : ""}>Previous</button><span class="small muted">Page ${Math.floor(data.offset/data.limit)+1} of ${Math.ceil(data.total/data.limit)}</span><button class="secondary" id="incident-next" ${data.offset+data.limit >= data.total ? "disabled" : ""}>Next</button>` : "";
        $("incident-prev")?.addEventListener("click",()=>{incidentOffset-=data.limit;loadIncidentRows();});
        $("incident-next")?.addEventListener("click",()=>{incidentOffset+=data.limit;loadIncidentRows();});
        $("incident-results").querySelectorAll(".incident-expand").forEach(b=>b.addEventListener("click",()=>{expandedIncidents.has(b.dataset.incident) ? expandedIncidents.delete(b.dataset.incident) : expandedIncidents.add(b.dataset.incident);loadIncidentRows();}));
        $("incident-results").querySelectorAll(".dismiss-email").forEach(b=>b.addEventListener("click",async()=>{
            if (!confirm("Dismiss this email notification without sending it again? This does not close or recover the incident. For uncertain delivery, check the mailbox first.")) return;
            b.disabled=true;
            try {await api(`/api/events/${encodeURIComponent(b.dataset.id)}/review`,{});await refresh();}
            catch(err) {message(err.message,true);b.disabled=false;}
        }));
    } catch(err) {
        if (request === incidentRequest && page === "alerts") {
            $("incident-list-status").textContent = "Could not update the list: " + err.message;
            $("incident-results").innerHTML = ""; $("incident-pagination").innerHTML = "";
        }
    }
}

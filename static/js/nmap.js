function runNmap(ip, domain) {
    // Show loading state on the button
    const nmapBtn = document.querySelector(`[data-ip="${ip}"]`);
    const originalText = nmapBtn.innerHTML;
    nmapBtn.innerHTML = `
        <div class="spinner-border spinner-border-sm me-1" role="status">
            <span class="visually-hidden">Loading...</span>
        </div>
        Running...
    `;
    nmapBtn.disabled = true;

    showNmapModal({
        output: `
            🔍 Scan running...
        `
    }, ip, domain);

    fetch(`/nmap/${ip}`)
        .then(response => response.text())
        .then(text => {
            if (text.trim().length > 0) {
                showNmapModal({ output: text }, ip, domain);
            } else {
                showNmapModal({ error: "No output from Nmap." }, ip, domain);
            }
        })
        .catch(error => {
            console.error('Nmap error:', error);
            showNmapModal({ error: error.message }, ip, domain);
        })
        .finally(() => {
            nmapBtn.innerHTML = originalText;
            nmapBtn.disabled = false;
        });

}

function rerunNmap(ip, domain) {
    // Show loading state on the button
    const nmapBtn = document.querySelector(`[data-ip="${ip}"]`);
    const originalText = nmapBtn.innerHTML;
    nmapBtn.innerHTML = `
        <div class="spinner-border spinner-border-sm me-1" role="status">
            <span class="visually-hidden">Loading...</span>
        </div>
        Re-running...
    `;
    nmapBtn.disabled = true;

    showNmapModal({
        output: `
            🔍 Re-running scan...
        `
    }, ip, domain);

    fetch(`/renmap/${ip}`)
        .then(response => response.text())
        .then(text => {
            if (text.trim().length > 0) {
                showNmapModal({ output: text }, ip, domain);
            } else {
                showNmapModal({ error: "No output from Nmap." }, ip, domain);
            }
        })
        .catch(error => {
            console.error('Nmap error:', error);
            showNmapModal({ error: error.message }, ip, domain);
        })
        .finally(() => {
            nmapBtn.innerHTML = originalText;
            nmapBtn.disabled = false;
        });
}

const nmapModalInstance = new bootstrap.Modal(document.getElementById("nmapModal"));
let nmapModalShown = false;

function showNmapModal(nmapData, ip = "N/A", domain = "N/A") {
    const modalTitle = document.getElementById("nmapModalTitle");
    const modalBody = document.getElementById("nmapModalBody");

    modalTitle.textContent = `Nmap Results for ${domain} (${ip})`;

    if (nmapData.error) {
        modalBody.innerHTML = `
            <div class="alert alert-danger">
                <h5>❌ Error running Nmap</h5>
                <p>${nmapData.error}</p>
            </div>
        `;
    } else {
        modalBody.innerHTML = `
            <div class="nmap-results">
                <div class="mb-3">
                    <h6>Target Information</h6>
                    <div class="bg-dark p-3 rounded">
                        <div class="text-info">Domain: <span class="text-white">${domain}</span></div>
                        <div class="text-info">IP Address: <span class="text-white">${ip}</span></div>
                    </div>
                </div>
                
                <div class="mb-3">
                    <h6>Scan Results</h6>
                    <pre class="bg-dark text-light p-3 rounded" style="max-height: 400px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 0.9em;">${escapeHTML(nmapData.output)}</pre>
                </div>
                
                <div class="d-flex gap-2">
                    <button class="btn btn-sm btn-outline-secondary" onclick="copyNmapResults('${ip}')">
                        📋 Copy Results
                    </button>
                    <button class="btn btn-sm btn-outline-info" onclick="rerunNmap('${ip}', '${domain}')">
                        🔄 Re-run Scan
                    </button>
                </div>
            </div>
        `;
    }

    if (!nmapModalShown) {
        nmapModalInstance.show();
        nmapModalShown = true;
    }
}
// Handle modal close event to reset state
document.getElementById("nmapModal").addEventListener("hidden.bs.modal", () => {
    nmapModalShown = false;
});


function copyNmapResults(ip) {
    const el = document.querySelector('.nmap-results pre');
    if (!el) return;

    safeCopy(el.textContent, "Nmap results copied to clipboard!");
}

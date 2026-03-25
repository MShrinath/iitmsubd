function showCertModal(cert) {
    const modal = new bootstrap.Modal(document.getElementById("certModal"));
    const certBody = document.getElementById("certDetails");

    if (!cert) {
        certBody.innerHTML = `<div class="text-danger">No certificate info available.</div>`;
        modal.show();
        return;
    }

    if (cert.error) {
        certBody.innerHTML = `
            <div class="text-danger">
                ❌ Error retrieving certificate:<br>
                <code>${cert.error}</code>
            </div>
        `;
        modal.show();
        return;
    }

    const now = new Date();
    const validToDate = new Date(cert.valid_to);
    let validityClass = "text-success";

    if (validToDate < now) {
        validityClass = "text-danger"; // expired
    } else if ((validToDate - now) / (1000 * 60 * 60 * 24) < 30) {
        validityClass = "text-warning"; // expiring soon
    }

    // Create a more modern certificate display
    let content = `
        <div class="certificate-display">
            <div class="cert-header mb-4">
                <h4 class="text-info">${cert.subject_common_name}</h4>
                <div class="cert-status ${validToDate < now ? 'expired' : 'valid'}">
                    ${validToDate < now ? '❌ Expired' : '✅ Valid'}
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <div class="cert-field mb-3">
                        <div class="cert-label">Issuer</div>
                        <div class="cert-value">${cert.issuer_common_name || "N/A"}</div>
                    </div>
                    
                    <div class="cert-field mb-3">
                        <div class="cert-label">Valid From</div>
                        <div class="cert-value text-success">${formatDate(cert.valid_from)}</div>
                    </div>
                    
                    <div class="cert-field mb-3">
                        <div class="cert-label">Valid To</div>
                        <div class="cert-value ${validityClass}">${formatDate(cert.valid_to)}</div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="cert-field mb-3">
                        <div class="cert-label">Serial Number</div>
                        <div class="cert-value font-monospace">${cert.serial_number || "N/A"}</div>
                    </div>
                    
                    <div class="cert-field">
                        <div class="cert-label">Alternative Names</div>
                        <div class="cert-value alt-names">
                            ${renderAltNames(cert.full_raw?.subjectAltName)}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Raw JSON + Copy Button
    const rawJSON = JSON.stringify(cert, null, 2);
    content += `
        <div class="mt-4 pt-3 border-top">
            <button class="btn btn-sm btn-outline-secondary me-2" type="button" data-bs-toggle="collapse" data-bs-target="#rawCertCollapse">
                🔍 Show Raw
            </button>
            <button class="btn btn-sm btn-outline-dark" onclick="copyRawCertJSON()">📋 Copy Raw to Clipboard</button>

            <div class="collapse mt-2" id="rawCertCollapse">
                <pre id="rawCertData" style="background-color: var(--bg-secondary); padding: 1em; border: 1px solid var(--border-color); max-height: 300px; overflow-y: auto;">${rawJSON}</pre>
            </div>
        </div>
    `;

    certBody.innerHTML = content;
    modal.show();
}

function renderAltNames(altNamesArray) {
    if (!altNamesArray || !Array.isArray(altNamesArray) || altNamesArray.length === 0) {
        return '<span class="text-muted">None</span>';
    }
    
    const names = altNamesArray.map(alt => alt[1]);
    if (names.length <= 3) {
        return names.map(name => `<span class="badge bg-light text-dark mb-1 me-1">${name}</span>`).join(' ');
    } else {
        const visibleNames = names.slice(0, 3);
        const hiddenCount = names.length - 3;
        
        return `
            ${visibleNames.map(name => `<span class="badge bg-light text-dark mb-1 me-1">${name}</span>`).join(' ')}
            <button class="btn btn-sm btn-link p-0" 
                    type="button" 
                    data-bs-toggle="collapse" 
                    data-bs-target="#moreAltNames">
                +${hiddenCount} more
            </button>
            <div class="collapse mt-1" id="moreAltNames">
                ${names.slice(3).map(name => `<span class="badge bg-light text-dark mb-1 me-1">${name}</span>`).join(' ')}
            </div>
        `;
    }
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function copyRawCertJSON() {
    const raw = document.getElementById("rawCertData");
    if (!raw) return;

    safeCopy(raw.textContent, "Certificate data copied to clipboard!");
}

// Subfinder-specific JavaScript
// This file contains all subfinder-specific rendering and functionality

// Load results on page load
document.addEventListener('DOMContentLoaded', () => {
    loadResults();
    
    // Rescan button handler
    document.getElementById("rescanBtn").addEventListener("click", startRescan);
});

function loadResults() {
    // Show loading state
    const container = document.getElementById("reportSection");
    container.innerHTML = `
        <div class="text-center p-5">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Loading subfinder data...</p>
        </div>
    `;
    
    fetch("/results/subfinder")
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            renderReport(data);
        })
        .catch(error => {
            container.innerHTML = `
                <div class="alert alert-danger">
                    <h5>❌ Error loading results</h5>
                    <p>${error.message}</p>
                    <button class="btn btn-warning mt-2" onclick="startRescan()">Run Initial Scan</button>
                </div>
            `;
        });
}

function renderReport(data) {
    const container = document.getElementById("reportSection");
    container.innerHTML = "";

    const stats = analyzeDomainData(data);
    document.getElementById("domainCount").textContent = stats.count;

    container.appendChild(renderStatsChartSection(stats));
    container.appendChild(renderDomainsHeader(stats.count));
    container.appendChild(renderSearchBar());
    
    const filterButtons = renderFilterButtons();
    container.appendChild(filterButtons);
    container.appendChild(renderStatusLegend());

    setupFilterFunctionality(filterButtons);
    setupSearchFunctionality();

    const row = renderDomainCardsGrid(data, stats);
    container.appendChild(row);

    renderCertChart(stats.countOk, stats.countWarning, stats.countError);
    renderTechStackChart(stats.techStackCounts);
    addThemeToggle();
}

// ========================================
// DATA ANALYSIS
// ========================================
function analyzeDomainData(data) {
    const now = new Date();
    const stats = {
        count: data.length,
        httpsOnly: [],
        httpOnly: [],
        expiringSoon: [],
        noCert: [],
        certExpired: [],
        certExpiredDomains: [],
        totalInvalidCert: 0,
        totalInvalidCertDomains: [],
        countOk: 0,
        countWarning: 0,
        countError: 0,
        techStackCounts: {}
    };

    data.forEach(item => {
        const httpStatus = item.httpstatus;  // FIX: lowercase
        const httpsStatus = item.httpsstatus;  // FIX: lowercase
        const certDetails = item.cert_details;
        
        // Collect tech stack statistics
        if (item.techstack && Array.isArray(item.techstack)) {
            item.techstack.forEach(tech => {
                if (tech && tech !== "Error" && tech !== "No technologies found") {
                    stats.techStackCounts[tech] = (stats.techStackCounts[tech] || 0) + 1;
                }
            });
        }
        
        // Check if certificate has error or is expired
        const certError = certDetails && certDetails.error ? certDetails.error.toLowerCase() : "";
        const certExpired = certDetails && certDetails.expired === "true";
        const isCertExpired = certError.includes("expired") || certExpired;

        if (isCertExpired) {
            stats.certExpired.push(item.subdomain);
            stats.certExpiredDomains.push(item.subdomain);
        }

        // Categorize by protocol availability - FIX: Check for valid status codes
        const httpHasResponse = httpStatus && httpStatus !== "timeout" && !isNaN(parseInt(httpStatus));
        const httpsHasResponse = httpsStatus && httpsStatus !== "timeout" && !isNaN(parseInt(httpsStatus));
        
        if (httpsHasResponse && !httpHasResponse) {
            stats.httpsOnly.push(item.subdomain);
        }
        if (httpHasResponse && !httpsHasResponse) {
            stats.httpOnly.push(item.subdomain);
        }

        // Check certificate validity
        if (!certDetails || certDetails.error || certDetails["@type"] === undefined) {
            stats.noCert.push(item.subdomain);
            stats.totalInvalidCert++;
            stats.totalInvalidCertDomains.push(item.subdomain);
        }

        // Check for expiring soon certificates - FIX: Better date parsing
        if (certDetails && certDetails["not-valid-after"] && !certError) {
            try {
                // Parse date format like "Aug 28 03:33:53 2025 GMT"
                const expiryDate = new Date(certDetails["not-valid-after"]);
                if (!isNaN(expiryDate.getTime())) {
                    const diffDays = (expiryDate - now) / (1000 * 60 * 60 * 24);
                    // Include certs that expire within 30 days (future) OR expired within last 30 days (recently expired)
                    if (Math.abs(diffDays) < 30) {
                        stats.expiringSoon.push(item.subdomain);
                    }
                }
            } catch (e) {
                // Ignore invalid dates
                console.warn(`Failed to parse date for ${item.subdomain}:`, certDetails["not-valid-after"]);
            }
        }
    });

    return stats;
}

// ========================================
// RENDER SECTIONS
// ========================================
function renderStatsChartSection(stats) {
    const section = document.createElement("div");
    section.className = "mb-4";
    section.innerHTML = `
        <div class="row g-4 align-items-center">
            <div class="col-md-8">
                ${renderStatsCards(stats)}
            </div>
            <div class="col-md-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">Domain Status</h5>
                        <div class="chart-container">
                            <canvas id="certDonutChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="row g-4 mt-2">
            <div class="col-12">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">📊 Top Technologies Detected</h5>
                        <div class="chart-container" style="position: relative; height: 400px;">
                            <canvas id="techStackChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    return section;
}

function renderStatsCards(stats) {
    const cards = [
        { 
            title: '🔔 Certificates Expiring Soon', 
            count: stats.expiringSoon.length, 
            domains: stats.expiringSoon, 
            label: 'Expiring Soon Domains', 
            class: 'border-danger' 
        },
        { 
            title: '🌐 HTTP Service Unavailable', 
            count: stats.httpsOnly.length, 
            domains: stats.httpsOnly, 
            label: 'No HTTP Domains', 
            class: 'border-warning', 
            proto: 'https' 
        },
        { 
            title: '🔓 Insecure (HTTP Only)', 
            count: stats.httpOnly.length, 
            domains: stats.httpOnly, 
            label: 'HTTP Only Domains', 
            class: 'border-warning', 
            proto: 'http' 
        },
        { 
            title: '🛑 Certificate Expired', 
            count: stats.certExpiredDomains.length, 
            domains: stats.certExpiredDomains, 
            label: 'Expired Certificate Domains', 
            class: 'border-danger', 
            proto: 'http' 
        },
        { 
            title: '🔐 Certificate Verification Failed', 
            count: stats.totalInvalidCert, 
            domains: stats.totalInvalidCertDomains, 
            label: 'Invalid Certificate Domains', 
            class: 'border-warning', 
            proto: 'http' 
        }
    ];

    return `
        <div class="row g-3 mb-4">
            ${cards.map(card => `
                <div class="col-md-4">
                    <div class="card text-bg-light ${card.class} h-100">
                        <div class="card-body">
                            <h5 class="card-title">${card.title}</h5>
                            <p class="fs-4 fw-semibold">${card.count}</p>
                            ${renderDomainPopupButton(card.domains, card.label, card.proto || 'https')}
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

function renderDomainsHeader(count) {
    const header = document.createElement("h3");
    header.className = "mb-3 mt-4";
    header.innerHTML = `Domain Status <span class="badge bg-secondary">${count}</span>`;
    return header;
}

function renderSearchBar() {
    const searchBar = document.createElement("div");
    searchBar.className = "mb-4";
    searchBar.innerHTML = `
        <div class="input-group">
            <span class="input-group-text">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-search" viewBox="0 0 16 16">
                    <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z"/>
                </svg>
            </span>
            <input type="text" class="form-control" id="domainSearch" placeholder="Search domains...">
        </div>
    `;
    return searchBar;
}

function renderFilterButtons() {
    const filterButtons = document.createElement("div");
    filterButtons.className = "mb-4 btn-group";
    filterButtons.innerHTML = `
        <button class="btn btn-outline-secondary active" data-filter="all">All</button>
        <button class="btn btn-outline-success" data-filter="ok">OK</button>
        <button class="btn btn-outline-warning" data-filter="warning">Warnings</button>
        <button class="btn btn-outline-danger" data-filter="error">Errors</button>
    `;
    return filterButtons;
}

function renderStatusLegend() {
    const legend = document.createElement("div");
    legend.className = "mb-4";
    legend.innerHTML = `
        <div class="card shadow-sm status-legend">
            <div class="card-body">
                <div class="row g-3">
                    <div class="col-md-4">
                        <div class="d-flex align-items-center">
                            <span class="badge bg-success me-3" style="width: 2.2rem; height: 2.2rem; display: flex; align-items: center; justify-content: center;">✅</span>
                            <div>
                                <strong>OK</strong><br>
                                All checks passed: HTTP/HTTPS responses are successful, certificate is valid & not expiring soon.
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="d-flex align-items-center">
                            <span class="badge bg-warning text-dark me-3" style="width: 2.2rem; height: 2.2rem; display: flex; align-items: center; justify-content: center;">⚠️</span>
                            <div>
                                <strong>Warning</strong><br>
                                One or more issues: non-200 responses, timeouts, or certificate expiring soon.
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="d-flex align-items-center">
                            <span class="badge bg-danger me-3" style="width: 2.2rem; height: 2.2rem; display: flex; align-items: center; justify-content: center;">❌</span>
                            <div>
                                <strong>Error</strong><br>
                                Certificate is missing or invalid, HTTPS is broken.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    return legend;
}

function renderTechStackSection() {
    const section = document.createElement("div");
    section.className = "mb-4 mt-5";
    section.innerHTML = `
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">📊 Top Technologies Detected</h5>
                <div class="chart-container" style="height: 500px;">
                    <canvas id="techStackChart"></canvas>
                </div>
            </div>
        </div>
    `;
    return section;
}

function renderNetworkTopologySection() {
    const section = document.createElement("div");
    section.className = "mb-4 mt-4";
    section.innerHTML = `
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">🗺️ Subdomain Clusters</h5>
                <div class="text-muted small mb-3">
                    Shows top 12 subdomain prefixes grouped by pattern. Hover for details about each cluster.
                </div>
                <div class="chart-container" style="height: 450px;">
                    <canvas id="networkTopologyChart"></canvas>
                </div>
            </div>
        </div>
    `;
    return section;
}

// ========================================
// INTERACTIVITY
// ========================================
function setupFilterFunctionality(filterButtons) {
    filterButtons.querySelectorAll('button').forEach(btn => {
        btn.addEventListener('click', (e) => {
            filterButtons.querySelectorAll('button').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            
            const filter = e.target.getAttribute('data-filter');
            const cards = document.querySelectorAll('.domain-card');
            
            cards.forEach(card => {
                if (filter === 'all' || card.classList.contains(filter)) {
                    card.style.display = '';
                } else {
                    card.style.display = 'none';
                }
            });
        });
    });
}

function setupSearchFunctionality() {
    document.getElementById('domainSearch').addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        const cards = document.querySelectorAll('.domain-card');
        
        cards.forEach(card => {
            const domain = card.getAttribute('data-domain').toLowerCase();
            card.style.display = domain.includes(searchTerm) ? '' : 'none';
        });
    });
}

// ========================================
// DOMAIN CARDS
// ========================================
function renderDomainCardsGrid(data, stats) {
    const row = document.createElement("div");
    row.className = "row g-4";

    data.forEach(item => {
        const status = calculateDomainStatus(item);
        const col = createDomainCard(item, status);
        
        row.appendChild(col);

        if (status.statusClass === "ok") stats.countOk++;
        else if (status.statusClass === "warning") stats.countWarning++;
        else if (status.statusClass === "error") stats.countError++;
    });

    return row;
}

function calculateDomainStatus(item) {
    const httpStatus = item.httpstatus;  // FIX: lowercase
    const httpsStatus = item.httpsstatus;  // FIX: lowercase
    const certDetails = item.cert_details;
    
    // Parse status codes
    const httpOk = httpStatus && httpStatus !== "timeout" && parseInt(httpStatus) === 200;
    const httpsOk = httpsStatus && httpsStatus !== "timeout" && parseInt(httpsStatus) === 200;
    
    // Check certificate
    const certOk = certDetails && !certDetails.error && certDetails["@type"] !== undefined;
    const certExpired = certDetails && (certDetails.expired === "true" || 
                                       (certDetails.error && certDetails.error.toLowerCase().includes("expired")));
    
    // Check expiration
    let notExpiring = false;
    if (certDetails && certDetails["not-valid-after"] && !certExpired) {
        try {
            const expiryDate = new Date(certDetails["not-valid-after"]);
            const diffDays = (expiryDate - new Date()) / (1000 * 60 * 60 * 24);
            notExpiring = diffDays >= 30;
        } catch (e) {
            notExpiring = false;
        }
    }

    let domainClass = "border-success";
    let statusClass = "ok";
    let statusOk = true;

    // Error conditions (most severe)
    if (!certOk || certExpired) {
        domainClass = "border-danger";
        statusClass = "error";
        statusOk = false;
    }
    // Warning conditions
    else if (!httpOk || !httpsOk || (certOk && !notExpiring)) {
        domainClass = "border-warning";
        statusClass = "warning";
        statusOk = false;
    }
    // All OK
    else if (httpOk && httpsOk && certOk && notExpiring) {
        domainClass = "border-success";
        statusClass = "ok";
        statusOk = true;
    }

    return { domainClass, statusClass, statusOk };
}

function createDomainCard(item, status) {
    const col = document.createElement("div");
    col.className = "col-md-6 col-lg-4 domain-card " + status.statusClass;
    col.setAttribute('data-domain', item.subdomain);

    const card = document.createElement("div");
    card.className = `card h-100 ${status.domainClass}`;
    card.innerHTML = buildDomainCardHTML(item, status.statusOk);

    attachCardEventListeners(card, item);
    col.appendChild(card);
    return col;
}

function buildDomainCardHTML(item, statusOk) {
    const httpStatus = item.httpstatus;  // FIX: lowercase
    const httpsStatus = item.httpsstatus;  // FIX: lowercase
    
    return `
        <div class="card-body" id="card-${item.subdomain.replace(/\W/g, '-')}" data-domain="${item.subdomain}">
            <h5 class="card-title d-flex align-items-center">
                <span class="status-icon me-2">${statusOk ? "✅" : "⚠️"}</span>
                <span class="domain-name">${formatDomainName(item.subdomain)}</span>
            </h5>
            <h6 class="card-subtitle mb-2 text-muted d-flex align-items-center">
                <span class="badge domain-badge me-2">${item.ip?.join(", ") || "N/A"}</span>
            </h6>
            <div class="mt-3">
                <div class="d-flex justify-content-between mb-2 align-items-center">
                    <strong>HTTP:</strong> 
                    ${renderStatusBadge(httpStatus)}
                </div>
                <div class="d-flex justify-content-between mb-2 align-items-center">
                    <strong>HTTPS:</strong> 
                    ${renderStatusBadge(httpsStatus)}
                </div>
                <div class="d-flex justify-content-between mb-3 align-items-center">
                    <strong>Certificate:</strong> 
                    ${renderCertStatusBadge(item.cert_details)}
                </div>
                ${item.techstack && item.techstack.length > 0 ? `
                    <div class="d-flex justify-content-between mb-2 align-items-center">
                        <strong>Tech Stack:</strong> 
                        <span class="badge bg-info">${item.techstack.length} found</span>
                    </div>
                ` : ''}
            </div>
            <div class="d-flex mt-3 gap-2 flex-wrap">
                <a href="https://${item.subdomain}" target="_blank" class="btn btn-sm btn-outline-primary">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-box-arrow-up-right" viewBox="0 0 16 16">
                        <path fill-rule="evenodd" d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/>
                        <path fill-rule="evenodd" d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/>
                    </svg>
                    Visit
                </a>
                ${item.cert_details && !item.cert_details.error ? `
                    <button class="btn btn-sm btn-outline-info cert-details-btn">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-lock" viewBox="0 0 16 16">
                            <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.775 11.775 0 0 1-2.517 2.453 7.159 7.159 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7.158 7.158 0 0 1-1.048-.625 11.777 11.777 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 62.456 62.456 0 0 1 5.072.56z"/>
                            <path d="M9.5 6.5a1.5 1.5 0 0 1-1 1.415l.385 1.99a.5.5 0 0 1-.491.595h-.788a.5.5 0 0 1-.49-.595l.384-1.99a1.5 1.5 0 1 1 2-1.415z"/>
                        </svg>
                        Cert
                    </button>
                ` : ''}
                ${item.techstack && item.techstack.length > 0 ? `
                    <button class="btn btn-sm btn-outline-secondary tech-details-btn">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                            <path d="M5 0a.5.5 0 0 1 .5.5V2h1V.5a.5.5 0 0 1 1 0V2h1V.5a.5.5 0 0 1 1 0V2h1V.5a.5.5 0 0 1 1 0V2A2.5 2.5 0 0 1 14 4.5h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14a2.5 2.5 0 0 1-2.5 2.5v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14A2.5 2.5 0 0 1 2 11.5H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2A2.5 2.5 0 0 1 4.5 2V.5A.5.5 0 0 1 5 0zm-.5 3A1.5 1.5 0 0 0 3 4.5v7A1.5 1.5 0 0 0 4.5 13h7a1.5 1.5 0 0 0 1.5-1.5v-7A1.5 1.5 0 0 0 11.5 3h-7zM5 6.5A1.5 1.5 0 0 1 6.5 5h3A1.5 1.5 0 0 1 11 6.5v3A1.5 1.5 0 0 1 9.5 11h-3A1.5 1.5 0 0 1 5 9.5v-3zM6.5 6a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5h-3z"/>
                        </svg>
                        Tech
                    </button>
                ` : ''}
                ${item.ip && item.ip.length > 0 ? `
                    <button class="btn btn-sm btn-outline-warning nmap-btn" data-ip="${item.ip[0]}">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-radar" viewBox="0 0 16 16">
                            <path d="M6.634 1.135A7 7 0 0 1 15 8a.5.5 0 0 1-1 0 6 6 0 1 0-6.5 5.98v-1.005A5 5 0 1 1 13 8a.5.5 0 0 1-1 0 4 4 0 1 0-4.5 3.969v-1.011A2.999 2.999 0 1 1 11 8a.5.5 0 0 1-1 0 2 2 0 1 0-2.5 1.936v-.998A1 1 0 1 1 9 8a.5.5 0 0 1-1 0 .5.5 0 0 0-1-1v5.5a.5.5 0 0 1-1 0V8a1.5 1.5 0 1 1 1.5-1.5"/>
                        </svg>
                        Nmap
                    </button>
                ` : ''}
            </div>
        </div>
    `;
}

function attachCardEventListeners(card, item) {
    const certBtn = card.querySelector('.cert-details-btn');
    if (certBtn && item.cert_details && !item.cert_details.error) {
        certBtn.addEventListener("click", () => showSubfinderCertModal(item.cert_details, item.subdomain));
    }

    const techBtn = card.querySelector('.tech-details-btn');
    if (techBtn && item.techstack) {
        techBtn.addEventListener("click", () => showTechModal(item.techstack, item.subdomain));
    }

    const nmapBtn = card.querySelector('.nmap-btn');
    if (nmapBtn && item.ip) {
        nmapBtn.addEventListener("click", () => runNmap(item.ip[0], item.subdomain));
    }
}

function showTechModal(techstack, subdomain) {
    const modal = new bootstrap.Modal(document.getElementById("techModal"));
    const modalBody = document.getElementById("techDetails");
    
    modalBody.innerHTML = `
        <div class="alert alert-info">
            <strong>Domain:</strong> ${escapeHTML(subdomain)}
        </div>
        <h6>Detected Technologies:</h6>
        <ul class="list-group">
            ${techstack.map(tech => `
                <li class="list-group-item">${escapeHTML(tech)}</li>
            `).join('')}
        </ul>
    `;
    
    modal.show();
}

function showSubfinderCertModal(certDetails, subdomain) {
    const modal = new bootstrap.Modal(document.getElementById("certModal"));
    const modalBody = document.getElementById("certDetails");
    
    if (!certDetails) {
        modalBody.innerHTML = `<div class="text-danger">No certificate info available.</div>`;
        modal.show();
        return;
    }

    if (certDetails.error) {
        modalBody.innerHTML = `
            <div class="text-danger">
                ❌ Error retrieving certificate:<br>
                <code>${escapeHTML(certDetails.error)}</code>
            </div>
        `;
        modal.show();
        return;
    }
    
    const subject = certDetails.subject || subdomain;
    const issuer = certDetails.issuer || 'N/A';
    const notBefore = certDetails["not-valid-before"] || 'N/A';
    const notAfter = certDetails["not-valid-after"] || 'N/A';
    const algorithm = certDetails["signature-algorithm"] || 'N/A';
    const selfSigned = certDetails["self-signed"] === "true" ? "Yes" : "No";
    const expired = certDetails.expired === "true";
    
    const now = new Date();
    const validToDate = new Date(notAfter);
    let validityClass = "text-success";
    let validityStatus = "✅ Valid";
    
    if (validToDate < now || expired) {
        validityClass = "text-danger";
        validityStatus = "❌ Expired";
    } else if ((validToDate - now) / (1000 * 60 * 60 * 24) < 30) {
        validityClass = "text-warning";
        validityStatus = "⚠️ Expiring Soon";
    }
    
    // Create a more modern certificate display (knockpy style)
    let content = `
        <div class="certificate-display">
            <div class="cert-header mb-4">
                <h4 class="text-info">${escapeHTML(subject)}</h4>
                <div class="cert-status ${expired || validToDate < now ? 'expired' : 'valid'}">
                    ${validityStatus}
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <div class="cert-field mb-3">
                        <div class="cert-label">Issuer</div>
                        <div class="cert-value">${escapeHTML(issuer)}</div>
                    </div>
                    
                    <div class="cert-field mb-3">
                        <div class="cert-label">Valid From</div>
                        <div class="cert-value text-success">${escapeHTML(notBefore)}</div>
                    </div>
                    
                    <div class="cert-field mb-3">
                        <div class="cert-label">Valid To</div>
                        <div class="cert-value ${validityClass}">${escapeHTML(notAfter)}</div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="cert-field mb-3">
                        <div class="cert-label">Signature Algorithm</div>
                        <div class="cert-value font-monospace">${escapeHTML(algorithm)}</div>
                    </div>
                    
                    <div class="cert-field mb-3">
                        <div class="cert-label">Self-Signed</div>
                        <div class="cert-value">${selfSigned}</div>
                    </div>
                    
                    ${certDetails.altnames ? `
                        <div class="cert-field">
                            <div class="cert-label">Alternative Names</div>
                            <div class="cert-value alt-names">
                                <span class="badge bg-light text-dark mb-1">${escapeHTML(certDetails.altnames)}</span>
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
    
    // Raw JSON + Copy Button
    const rawJSON = JSON.stringify(certDetails, null, 2);
    content += `
        <div class="mt-4 pt-3 border-top">
            <button class="btn btn-sm btn-outline-secondary me-2" type="button" data-bs-toggle="collapse" data-bs-target="#rawCertCollapse">
                🔍 Show Raw
            </button>
            <button class="btn btn-sm btn-outline-dark" onclick="copySubfinderCertJSON()">📋 Copy Raw to Clipboard</button>

            <div class="collapse mt-2" id="rawCertCollapse">
                <pre id="rawCertData" style="background-color: var(--bg-secondary); padding: 1em; border: 1px solid var(--border-color); max-height: 300px; overflow-y: auto;">${escapeHTML(rawJSON)}</pre>
            </div>
        </div>
    `;
    
    modalBody.innerHTML = content;
    modal.show();
}

function copySubfinderCertJSON() {
    const raw = document.getElementById("rawCertData");
    if (!raw) return;
    
    safeCopy(raw.textContent, "Certificate data copied to clipboard!");
}

function addThemeToggle() {
    if (!document.querySelector('.theme-toggle')) {
        const header = document.querySelector('header');
        const themeToggle = document.createElement('button');
        themeToggle.className = 'theme-toggle';
        themeToggle.setAttribute('aria-label', 'Toggle dark mode');
        themeToggle.innerHTML = currentTheme === 'dark' 
            ? '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 18C8.68629 18 6 15.3137 6 12C6 8.68629 8.68629 6 12 6C15.3137 6 18 8.68629 18 12C18 15.3137 15.3137 18 12 18ZM12 16C14.2091 16 16 14.2091 16 12C16 9.79086 14.2091 8 12 8C9.79086 8 8 9.79086 8 12C8 14.2091 9.79086 16 12 16ZM11 1H13V4H11V1ZM11 20H13V23H11V20ZM3.51472 4.92893L4.92893 3.51472L7.05025 5.63604L5.63604 7.05025L3.51472 4.92893ZM16.9497 18.364L18.364 16.9497L20.4853 19.0711L19.0711 20.4853L16.9497 18.364ZM19.0711 3.51472L20.4853 4.92893L18.364 7.05025L16.9497 5.63604L19.0711 3.51472ZM5.63604 16.9497L7.05025 18.364L4.92893 20.4853L3.51472 19.0711L5.63604 16.9497ZM23 11V13H20V11H23ZM4 11V13H1V11H4Z"></path></svg>'
            : '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M10 7C10 10.866 13.134 14 17 14C18.9584 14 20.729 13.1957 21.9995 11.8995C22 11.933 22 11.9665 22 12C22 17.5228 17.5228 22 12 22C6.47715 22 2 17.5228 2 12C2 6.47715 6.47715 2 12 2C12.0335 2 12.067 2 12.1005 2.00049C10.8043 3.27105 10 5.04157 10 7ZM4 12C4 16.4183 7.58172 20 12 20C15.0583 20 17.7158 18.2839 19.062 15.7621C18.3945 15.9196 17.7035 16 17 16C12.0294 16 8 11.9706 8 7C8 6.29648 8.08036 5.60547 8.2379 4.938C5.71611 6.28423 4 8.9417 4 12Z"></path></svg>';
        
        themeToggle.addEventListener('click', toggleTheme);
        header.appendChild(themeToggle);
    }
}

function renderStatusBadge(status) {
    if (!status || status === "timeout") {
        return `<span class="badge bg-secondary">Timeout</span>`;
    }
    
    const code = parseInt(status);
    let badgeClass = 'bg-success';
    let icon = '✅';
    
    if (isNaN(code)) {
        return `<span class="badge bg-secondary">${escapeHTML(status)}</span>`;
    }
    
    if (code !== 200) {
        badgeClass = code >= 400 ? 'bg-danger' : 'bg-warning';
        icon = code >= 400 ? '❌' : '⚠️';
    }
    
    return `<span class="badge ${badgeClass}">${icon} ${code}</span>`;
}

function renderCertStatusBadge(certDetails) {
    if (!certDetails) {
        return `<span class="badge bg-danger">❌ No Cert</span>`;
    }
    
    if (certDetails.error) {
        return `<span class="badge bg-danger">❌ Error</span>`;
    }
    
    if (certDetails.expired === "true") {
        return `<span class="badge bg-danger">❌ Expired</span>`;
    }
    
    if (certDetails["not-yet-valid"] === "true") {
        return `<span class="badge bg-warning">⚠️ Not Yet Valid</span>`;
    }
    
    // Check if expiring soon
    if (certDetails["not-valid-after"]) {
        try {
            const expiryDate = new Date(certDetails["not-valid-after"]);
            const diffDays = (expiryDate - new Date()) / (1000 * 60 * 60 * 24);
            if (diffDays < 30 && diffDays > 0) {
                return `<span class="badge bg-warning">⚠️ Expiring Soon</span>`;
            }
        } catch (e) {
            // Ignore
        }
    }
    
    return `<span class="badge bg-success">✅ Valid</span>`;
}

function renderDomainPopupButton(domains, title, proto = "https") {
    if (domains.length === 0) return "";

    const buttonId = title.replace(/\s+/g, "") + "Btn";
    return `
        <button class="btn btn-sm btn-outline-secondary mt-2" type="button"
                onclick='showDomainList(${JSON.stringify(domains)}, "${title}", "${proto}")'>
            View Domains (${domains.length})
        </button>
    `;
}

function showDomainList(domains, title, proto = "https") {
    const modal = new bootstrap.Modal(document.getElementById("domainListModal"));
    const modalTitle = document.getElementById("domainListTitle");
    const modalBody = document.getElementById("domainListBody");

    modalTitle.textContent = title;
    modalBody.innerHTML = `
        <div class="input-group mb-3">
            <span class="input-group-text">Filter</span>
            <input type="text" class="form-control" id="domainListFilter" placeholder="Type to filter...">
        </div>
        <ul class="list-group domain-list">
            ${domains.map(domain => `
                <li class="list-group-item d-flex justify-content-between align-items-center">
                    <a href="#" onclick="scrollToDomain('${domain}'); return false;">${domain}</a>
                    <a href="${proto}://${domain}" target="_blank" class="btn btn-sm btn-outline-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-box-arrow-up-right" viewBox="0 0 16 16">
                            <path fill-rule="evenodd" d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/>
                            <path fill-rule="evenodd" d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/>
                        </svg>
                    </a>
                </li>
            `).join("")}
        </ul>
    `;

    // Add filter functionality
    setTimeout(() => {
        const filterInput = document.getElementById('domainListFilter');
        if (filterInput) {
            filterInput.focus();
            filterInput.addEventListener('input', (e) => {
                const filterValue = e.target.value.toLowerCase();
                const items = document.querySelectorAll('.domain-list .list-group-item');
                
                items.forEach(item => {
                    const domainText = item.textContent.toLowerCase();
                    if (domainText.includes(filterValue)) {
                        item.style.display = '';
                    } else {
                        item.style.display = 'none';
                    }
                });
            });
        }
    }, 300);

    modal.show();
}

function scrollToDomain(domain) {
    const id = `card-${domain.replace(/\W/g, '-')}`;
    const el = document.getElementById(id);

    // Close the popup/modal if open
    const summaryModalEl = document.getElementById("domainListModal");
    const summaryModal = bootstrap.Modal.getInstance(summaryModalEl);
    if (summaryModal) summaryModal.hide();

    // Scroll and highlight
    if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });

        el.classList.add("border-3", "border-info");
        el.style.transition = "box-shadow 0.4s ease";
        el.style.boxShadow = "0 0 0.5rem 0.2rem rgba(13, 110, 253, 0.6)";

        setTimeout(() => {
            el.classList.remove("border-3", "border-info");
            el.style.boxShadow = "";
        }, 2000);
    }
}

function formatDomainName(domain) {
    domain = domain.replace(/^https?:\/\//, '');
    domain = domain.replace(/\/+$/, '');
    return `<code>${escapeHTML(domain)}</code>`;
}

function startRescan() {
    if (!confirm("Do you want to re-scan with Subfinder? This may take several minutes.")) return;

    const modal = new bootstrap.Modal(document.getElementById("scanModal"));
    const logBox = document.getElementById("scanLog");
    logBox.textContent = "🚀 Starting Subfinder scan...\n";
    modal.show();

    const source = new EventSource("/rescan/subfinder");

    source.onmessage = function (event) {
        logBox.textContent += event.data + "\n";
        logBox.scrollTop = logBox.scrollHeight;

        if (event.data.startsWith("✅") || event.data.includes("complete")) {
            source.close();
            setTimeout(() => {
                modal.hide();
                loadResults();
            }, 1500);
        }
    };

    source.onerror = function(error) {
        logBox.textContent += "\n❌ Connection error. Check server status.\n";
        source.close();
        setTimeout(() => modal.hide(), 3000);
    };
}

// ========================================
// TECH STACK CHART
// ========================================
function renderTechStackChart(techStackCounts) {
    const canvas = document.getElementById("techStackChart");
    if (!canvas) return;

    // Sort by count and get top 15
    const sorted = Object.entries(techStackCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15);

    if (sorted.length === 0) {
        canvas.parentElement.innerHTML = '<p class="text-muted text-center mt-4">No technology stack data available</p>';
        return;
    }

    const labels = sorted.map(([tech]) => tech);
    const data = sorted.map(([, count]) => count);

    // More vibrant gradient colors
    const colors = [
        '#FF6B9D', '#4ECDC4', '#FFE66D', '#A8E6CF', '#B19CD9',
        '#FF8B94', '#6C5CE7', '#00D2FF', '#FFA07A', '#98D8C8',
        '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B195', '#C06C84'
    ];

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Domains',
                data: data,
                backgroundColor: colors,
                borderColor: colors.map(c => c + 'DD'),
                borderWidth: 2,
                borderRadius: 8,
                borderSkipped: false,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    borderColor: '#ddd',
                    borderWidth: 1,
                    cornerRadius: 6,
                    padding: 12,
                    displayColors: true,
                    callbacks: {
                        title: function(context) {
                            return `🔧 ${context[0].label}`;
                        },
                        label: function(context) {
                            const count = context.parsed.x;
                            const total = data.reduce((a, b) => a + b, 0);
                            const percentage = ((count / total) * 100).toFixed(1);
                            return ` ${count} domain${count !== 1 ? 's' : ''} (${percentage}%)`;
                        }
                    }
                },
                title: {
                    display: true,
                    text: '🏆 Most Popular Technologies',
                    font: {
                        size: 16,
                        weight: 'bold'
                    },
                    color: '#333',
                    padding: {
                        top: 10,
                        bottom: 20
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                        font: {
                            size: 12
                        }
                    },
                    title: {
                        display: true,
                        text: '📊 Number of Domains',
                        font: {
                            size: 13,
                            weight: 'bold'
                        }
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)',
                        drawBorder: false
                    }
                },
                y: {
                    ticks: {
                        font: {
                            size: 12,
                            weight: '500'
                        },
                        color: '#555'
                    },
                    grid: {
                        display: false
                    }
                }
            },
            animation: {
                duration: 1500,
                easing: 'easeOutQuart'
            }
        }
    });
}

// ========================================
// NETWORK TOPOLOGY GRAPH
// ========================================
function renderNetworkTopology(data) {
    const canvas = document.getElementById("networkTopologyChart");
    if (!canvas) return;

    // Group subdomains by parent domain structure
    const topology = {};
    
    data.forEach(item => {
        const parts = item.subdomain.split('.');
        if (parts.length >= 2) {
            const prefix = parts[0];
            if (!topology[prefix]) {
                topology[prefix] = {
                    count: 0,
                    subdomains: [],
                    hasHTTPS: false,
                    hasCert: false,
                    techs: new Set()
                };
            }
            topology[prefix].count++;
            topology[prefix].subdomains.push(item.subdomain);
            
            if (item.httpsstatus && item.httpsstatus !== "timeout") {
                topology[prefix].hasHTTPS = true;
            }
            if (item.cert_details && !item.cert_details.error) {
                topology[prefix].hasCert = true;
            }
            if (item.techstack && Array.isArray(item.techstack)) {
                item.techstack.forEach(tech => {
                    if (tech && tech !== "Error" && tech !== "No technologies found") {
                        topology[prefix].techs.add(tech);
                    }
                });
            }
        }
    });

    // Sort by count and get top 12 for polar chart
    const sorted = Object.entries(topology)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 12);

    if (sorted.length === 0) {
        canvas.parentElement.innerHTML = '<p class="text-muted text-center mt-4">No topology data available</p>';
        return;
    }

    const labels = sorted.map(([prefix]) => prefix + '.*');
    const counts = sorted.map(([, data]) => data.count);
    
    // Beautiful gradient colors
    const colors = [
        '#FF6B9D', '#4ECDC4', '#FFE66D', '#A8E6CF', '#B19CD9',
        '#FF8B94', '#6C5CE7', '#00D2FF', '#FFA07A', '#98D8C8',
        '#F7DC6F', '#BB8FCE'
    ];

    // Store metadata for tooltips
    const metadata = sorted.map(([prefix, data]) => ({
        prefix: prefix,
        subdomains: data.subdomains,
        hasHTTPS: data.hasHTTPS,
        hasCert: data.hasCert,
        techCount: data.techs.size
    }));

    new Chart(canvas, {
        type: 'polarArea',
        data: {
            labels: labels,
            datasets: [{
                data: counts,
                backgroundColor: colors.map(c => c + 'CC'),
                borderColor: colors,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        font: {
                            size: 12,
                            weight: '500'
                        },
                        padding: 15,
                        usePointStyle: true,
                        pointStyle: 'rectRounded'
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.9)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    borderColor: '#fff',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 15,
                    callbacks: {
                        title: function(context) {
                            return `🗂️ ${context[0].label}`;
                        },
                        label: function(context) {
                            const meta = metadata[context.dataIndex];
                            return [
                                `Subdomains: ${context.raw}`,
                                `HTTPS: ${meta.hasHTTPS ? '✅' : '❌'}`,
                                `Certificate: ${meta.hasCert ? '✅' : '❌'}`,
                                `Technologies: ${meta.techCount}`
                            ];
                        },
                        afterBody: function(context) {
                            const meta = metadata[context[0].dataIndex];
                            if (meta.subdomains.length <= 3) {
                                return ['', '📍 Subdomains:', ...meta.subdomains.map(s => '  • ' + s)];
                            } else {
                                return ['', '📍 Sample:', ...meta.subdomains.slice(0, 3).map(s => '  • ' + s), `  +${meta.subdomains.length - 3} more`];
                            }
                        }
                    }
                }
            },
            scales: {
                r: {
                    beginAtZero: true,
                    ticks: {
                        display: true,
                        backdropColor: 'transparent',
                        font: {
                            size: 11
                        }
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.1)'
                    }
                }
            },
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1500,
                easing: 'easeOutQuart'
            }
        }
    });
}

function extractRootDomain(subdomain) {
    const parts = subdomain.split('.');
    if (parts.length >= 2) {
        return parts.slice(-2).join('.');
    }
    return subdomain;
}
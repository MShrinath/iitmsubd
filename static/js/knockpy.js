// Knockpy-specific JavaScript
// This file contains all knockpy-specific rendering and functionality

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
            <p class="mt-2">Loading domain data...</p>
        </div>
    `;
    
    fetch("/results/knockpy")
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
        countError: 0
    };

    data.forEach(item => {
        const httpStatus = item.http?.[0];
        const httpsStatus = item.https?.[0];
        const certStatus = item.cert?.[0];
        const certDetails = item.cert_details;
        const certError = certDetails && certDetails.error ? certDetails.error.toLowerCase() : "";
        const isCertExpired = certError.includes("certificate has expired");

        if (isCertExpired) {
            stats.certExpired.push(item.domain);
            stats.certExpiredDomains.push(item.domain);
        }

        if (httpsStatus && !httpStatus) stats.httpsOnly.push(item.domain);
        if (httpStatus && !httpsStatus) stats.httpOnly.push(item.domain);

        if (!certStatus) {
            stats.noCert.push(item.domain);
            stats.totalInvalidCert++;
            stats.totalInvalidCertDomains.push(item.domain);
        }

        if (certStatus && certDetails?.valid_to) {
            const expiryDate = new Date(certDetails.valid_to);
            const diffDays = (expiryDate - now) / (1000 * 60 * 60 * 24);
            if (diffDays < 30) stats.expiringSoon.push(item.domain);
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
                                All checks passed: HTTP/HTTPS responses are 200, certificate is valid & not expiring soon.
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="d-flex align-items-center">
                            <span class="badge bg-warning text-dark me-3" style="width: 2.2rem; height: 2.2rem; display: flex; align-items: center; justify-content: center;">⚠️</span>
                            <div>
                                <strong>Warning</strong><br>
                                One or more issues: non-200 responses or certificate expiring soon.
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
    const httpStatus = item.http?.[0];
    const httpsStatus = item.https?.[0];
    const certStatus = item.cert?.[0];
    const certDetails = item.cert_details;
    
    const httpOk = httpStatus === 200;
    const httpsOk = httpsStatus === 200;
    const certOk = certStatus === true;
    const notExpiring = certDetails?.valid_to 
        ? (new Date(certDetails.valid_to) - new Date()) / (1000 * 60 * 60 * 24) >= 30
        : false;

    let domainClass = "border-success";
    let statusClass = "ok";
    let statusOk = true;

    if (!httpOk || !httpsOk) {
        domainClass = "border-warning";
        statusClass = "warning";
        statusOk = false;
    }

    if (!certOk) {
        domainClass = "border-danger";
        statusClass = "error";
        statusOk = false;
    }

    if (certOk && !notExpiring) {
        domainClass = "border-warning";
        statusClass = "warning";
        statusOk = false;
    }

    if (httpOk && httpsOk && certOk && notExpiring) {
        domainClass = "border-success";
        statusClass = "ok";
        statusOk = true;
    }

    return { domainClass, statusClass, statusOk };
}

function createDomainCard(item, status) {
    const col = document.createElement("div");
    col.className = "col-md-6 col-lg-4 domain-card " + status.statusClass;
    col.setAttribute('data-domain', item.domain);

    const card = document.createElement("div");
    card.className = `card h-100 ${status.domainClass}`;
    card.innerHTML = buildDomainCardHTML(item, status.statusOk);

    attachCardEventListeners(card, item);
    col.appendChild(card);
    return col;
}

function buildDomainCardHTML(item, statusOk) {
    return `
        <div class="card-body" id="card-${item.domain.replace(/\W/g, '-')}" data-domain="${item.domain}">
            <h5 class="card-title d-flex align-items-center">
                <span class="status-icon me-2">${statusOk ? "✅" : "⚠️"}</span>
                <span class="domain-name">${formatDomainName(item.domain)}</span>
            </h5>
            <h6 class="card-subtitle mb-2 text-muted d-flex align-items-center">
                <span class="badge domain-badge me-2">${item.ip?.join(", ") || "N/A"}</span>
            </h6>
            <div class="mt-3">
                <div class="d-flex justify-content-between mb-2 align-items-center">
                    <strong>HTTP:</strong> 
                    ${renderHttpStatus(item.http)}
                </div>
                <div class="d-flex justify-content-between mb-2 align-items-center">
                    <strong>HTTPS:</strong> 
                    ${renderHttpStatus(item.https)}
                </div>
                <div class="d-flex justify-content-between mb-3 align-items-center">
                    <strong>Certificate:</strong> 
                    ${renderCertStatus(item.cert)}
                </div>
            </div>
            <div class="d-flex mt-3 gap-2">
                <a href="https://${item.domain}" target="_blank" class="btn btn-sm btn-outline-primary">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-box-arrow-up-right" viewBox="0 0 16 16">
                        <path fill-rule="evenodd" d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/>
                        <path fill-rule="evenodd" d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/>
                    </svg>
                    Visit
                </a>
                ${item.cert_details ? `
                    <button class="btn btn-sm btn-outline-info cert-details-btn">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-lock" viewBox="0 0 16 16">
                            <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.775 11.775 0 0 1-2.517 2.453 7.159 7.159 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7.158 7.158 0 0 1-1.048-.625 11.777 11.777 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 62.456 62.456 0 0 1 5.072.56z"/>
                            <path d="M9.5 6.5a1.5 1.5 0 0 1-1 1.415l.385 1.99a.5.5 0 0 1-.491.595h-.788a.5.5 0 0 1-.49-.595l.384-1.99a1.5 1.5 0 1 1 2-1.415z"/>
                        </svg>
                        Cert
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
    if (certBtn && item.cert_details) {
        certBtn.addEventListener("click", () => showCertModal(item.cert_details));
    }

    const nmapBtn = card.querySelector('.nmap-btn');
    if (nmapBtn && item.ip) {
        nmapBtn.addEventListener("click", () => runNmap(item.ip[0], item.domain));
    }
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

function renderHttpStatus(httpArray) {
    if (!httpArray || httpArray.length < 1 || httpArray[0] == null)
        return `<span class="badge bg-secondary">No Response</span>`;
    
    const code = httpArray[0];
    let badgeClass = 'bg-success';
    let icon = '✅';
    
    if (code !== 200) {
        badgeClass = 'bg-danger';
        icon = '❌';
    }
    
    return `<span class="badge ${badgeClass}">${icon} ${code}</span>`;
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
    if (!confirm("Do you want to re-scan? This may take several minutes.")) return;

    const modal = new bootstrap.Modal(document.getElementById("scanModal"));
    const logBox = document.getElementById("scanLog");
    logBox.textContent = "🚀 Starting scan...\n";
    modal.show();

    const source = new EventSource("/rescan/knockpy");

    source.onmessage = function (event) {
        logBox.textContent += event.data + "\n";
        logBox.scrollTop = logBox.scrollHeight;

        if (event.data.startsWith("✅")) {
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

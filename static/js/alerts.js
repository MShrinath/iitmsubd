function renderCertStatus(certArray) {
    if (!certArray) return `<span class="badge bg-secondary">Unknown</span>`;
    
    const valid = certArray[0];
    if (valid) {
        // Parse the date to check if it's expiring soon
        const expiryDate = new Date(certArray[1]);
        const now = new Date();
        const diffDays = (expiryDate - now) / (1000 * 60 * 60 * 24);
        
        let badgeClass = 'bg-success';
        let icon = '🔒';
        let formattedDate = new Date(certArray[1]).toLocaleDateString();
        
        if (diffDays < 30) {
            badgeClass = 'bg-warning';
            icon = '⚠️';
        }
        
        return `<span class="badge ${badgeClass}">${icon} ${formattedDate}</span>`;
    } else {
        return `<span class="badge bg-danger">❌ Missing</span>`;
    }
}



function renderCertChart(countOk, countWarning, countError) {
    // Get the chart context
    const ctx = document.getElementById('certDonutChart');
    if (!ctx) return;
    
    // Check if chart already exists and destroy it
    const existingChart = Chart.getChart(ctx);
    if (existingChart) {
        existingChart.destroy();
    }
    
    // Chart.js configuration
    const certChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['OK', 'WARNING', 'ERROR'],
            datasets: [{
                data: [countOk, countWarning, countError],
                backgroundColor: [
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-success'),
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-warning'),
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-danger')
                ],
                borderColor: [
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-success'),
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-warning'),
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-danger')
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: getComputedStyle(document.documentElement).getPropertyValue('--text-primary'),
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: false
                }
            },
            cutout: '70%',
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
}


function updateChartColors(chart) {
    chart.data.datasets[0].backgroundColor = [
        getComputedStyle(document.documentElement).getPropertyValue('--chart-success'),
        getComputedStyle(document.documentElement).getPropertyValue('--chart-warning'),
        getComputedStyle(document.documentElement).getPropertyValue('--chart-danger')
    ];
    chart.data.datasets[0].borderColor = [
        getComputedStyle(document.documentElement).getPropertyValue('--chart-success'),
        getComputedStyle(document.documentElement).getPropertyValue('--chart-warning'),
        getComputedStyle(document.documentElement).getPropertyValue('--chart-danger')
    ];
    
    chart.options.plugins.legend.labels.color = 
        getComputedStyle(document.documentElement).getPropertyValue('--text-primary');
    
    chart.update();
}
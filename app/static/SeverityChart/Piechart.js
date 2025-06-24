document.addEventListener('DOMContentLoaded', function () {
     console.log("PieChart.js loaded");
     console.log("productVulnerabilityData:", productVulnerabilityData);
     
    if (typeof productVulnerabilityData !== 'undefined' && Object.keys(productVulnerabilityData).length > 0) {
    // if (typeof productVulnerabilityData !== 'undefined') {
        const ctx = document.getElementById('productVulnerabilityPieChart').getContext('2d');

        const rawLabels = Object.keys(productVulnerabilityData);
        const labels = rawLabels.map(label => label.split(' ')[0]);  

        const data = Object.values(productVulnerabilityData);

        new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Number of Vulnerabilities',
                    data: data,
                    backgroundColor: [
                        'rgba(153, 102, 255, 0.7)',  // purple
                        'rgba(255, 99, 71, 0.7)',    // tomato red
                        'rgba(81, 210, 139, 0.7)',   // medium sea green
                        'rgba(243, 210, 64, 0.7)',    // dark orange
                        'rgba(100, 149, 237, 0.7)'   // cornflower blue
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            boxWidth: 20
                        }
                    },
                    title: {
                        display: true,
                        text: 'Vulnerabilities by Product',
                        font: {
                            size: 16,
                        }
                    }
                }
            }
        });
    } else {
        console.warn("No vulnerability data available");
    }
});

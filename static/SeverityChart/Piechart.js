document.addEventListener('DOMContentLoaded', function () {
     console.log("PieChart.js loaded");
     console.log("productVulnerabilityData:", productVulnerabilityData);
     
    if (typeof productVulnerabilityData !== 'undefined' && Object.keys(productVulnerabilityData).length > 0) {
    // if (typeof productVulnerabilityData !== 'undefined') {
        const ctx = document.getElementById('productVulnerabilityPieChart').getContext('2d');

        const labels = Object.keys(productVulnerabilityData);
        const data = Object.values(productVulnerabilityData);

        new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Number of Vulnerabilities',
                    data: data,
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(255, 159, 64, 0.7)',
                        'rgba(255, 205, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(54, 162, 235, 0.7)'
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

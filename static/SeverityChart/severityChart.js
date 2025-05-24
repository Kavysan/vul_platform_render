document.addEventListener('DOMContentLoaded', function() {
    if (typeof severityTotals !== 'undefined') {
        const ctx = document.getElementById('vulnerabilitySeverityChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Severity 1', 'Severity 2', 'Severity 3', 'Severity 4', 'Severity 5'],
                datasets: [{
                    data: [
                        severityTotals['Severity 1'],
                        severityTotals['Severity 2'],
                        severityTotals['Severity 3'],
                        severityTotals['Severity 4'],
                        severityTotals['Severity 5']
                    ],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(255, 159, 64, 0.7)',
                        'rgba(255, 205, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(54, 162, 235, 0.7)'
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(255, 159, 64, 1)',
                        'rgba(255, 205, 86, 1)',
                        'rgba(75, 192, 192, 1)',
                        'rgba(54, 162, 235, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Vulnerabilities',
                            font: {
                                weight: 'bold'  
                            }
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Severity Level',
                            font: {
                                weight: 'bold' 
                            }
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false 
                    },
                    title: {
                        display: true,
                        text: 'Vulnerability Distribution by Severity Level',
                        font: {
                            size: 16,
                        }
                    }
                }
            }
        });
    }
});

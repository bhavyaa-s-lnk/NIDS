<script>
const ctx = document.getElementById('mlChart').getContext('2d');

let mlChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Anomaly Score',
                data: [],
                borderWidth: 2,
                tension: 0.3,
                borderColor: 'blue',
                backgroundColor: 'transparent'
            },
            {
                label: "Threshold",
                data: [],
                borderDash: [5, 5],
                borderWidth: 2,
                borderColor: 'red',
                backgroundColor: 'transparent'
            }
        ]
    },
    options: {
        scales: {
            y: {
                title: {
                    display: true,
                    text: 'Score (lower = more anomalous)'
                }
            }
        }
    }
});

// Function to fetch data from Flask API and update chart
async function updateChart() {
    try {
        const res = await fetch('/ml_data');
        const data = await res.json();

        mlChart.data.labels = data.scores.map((_, i) => i);
        mlChart.data.datasets[0].data = data.scores;
        mlChart.data.datasets[1].data = data.scores.map(() => data.threshold);
        mlChart.update();
    } catch (err) {
        console.error("Error fetching ML data:", err);
    }
}

// Update every second
setInterval(updateChart, 1000);
</script>

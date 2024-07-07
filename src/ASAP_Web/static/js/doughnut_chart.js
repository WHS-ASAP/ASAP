document.addEventListener("DOMContentLoaded", function () {
  fetch("/api/vulnerability-by-type")
    .then((response) => response.json())
    .then((data) => {
      const ctx = document.getElementById("doughnutChart").getContext("2d");

      const total = data.counts.reduce((sum, count) => sum + count, 0);

      new Chart(ctx, {
        type: "doughnut",
        data: {
          labels: data.vuln_types,
          datasets: [
            {
              data: data.counts,
              backgroundColor: [
                "#FFB3BA", // Pastel Red
                "#FFDFBA", // Pastel Orange
                "#FFFFBA", // Pastel Yellow
                "#BAFFC9", // Pastel Green
                "#BAE1FF", // Pastel Blue
                "#E0BAFF", // Pastel Indigo
                "#FFC3FF", // Pastel Violet
              ],
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false, // Ensure it respects the CSS max dimensions
          plugins: {
            legend: {
              display: true,
              position: "top",
            },
            tooltip: {
              callbacks: {
                label: function (context) {
                  const label = context.label || "";
                  const value = context.raw || 0;
                  return `${label}: ${value}`;
                },
              },
            },
            datalabels: {
              display: false,
            },
            centerText: {
              total: `${total}`,
              text: `Total Found`,
              fontSizeTotal: 22, // Adjust font size as needed
              fontSizeText: 16, // Adjust font size as needed
              color: "#333", // Adjust color as needed
              fontFamily: "Open Sans",
            },
          },
        },
        plugins: [
          {
            id: "centerText",
            beforeDraw: function (chart) {
              const width = chart.width,
                height = chart.height,
                ctx = chart.ctx;

              ctx.restore();
              const options = chart.options.plugins.centerText;
              ctx.fillStyle = options.color || "#333";
              ctx.textBaseline = "middle";

              // Draw the total count
              ctx.font = `bold ${options.fontSizeTotal}px ${options.fontFamily}`;
              const totalX = Math.round((width - ctx.measureText(options.total).width) / 2),
                totalY = height / 1.5 - 10;
              ctx.fillText(options.total, totalX, totalY);

              // Draw the Total Vuln text
              ctx.font = `${options.fontSizeText}px ${options.fontFamily}`;
              const textX = Math.round((width - ctx.measureText(options.text).width) / 2),
                textY = height / 1.5 + 10;
              ctx.fillText(options.text, textX, textY);

              ctx.save();
            },
          },
        ],
      });
    });
});

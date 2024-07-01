class IntroModalButton extends HTMLElement {
  constructor() {
    super(); // 항상 최상위 생성자 호출 필수
    this.attachShadow({ mode: "open" }); // Shadow DOM
  }

  connectedCallback() {
    const buttons = JSON.parse(this.getAttribute("buttons"));

    this.shadowRoot.innerHTML = `
      <style>
        .buttons-container {
          display: flex;
          flex-wrap: wrap;
          justify-content: center;
          padding: 20px 0;
          border-bottom: 1px solid #e0e0e0;
        }
        .button-row {
          display: flex;
          justify-content: center;
          width: 100%;
          margin-bottom: 10px;
          gap: 25px; /* Default gap for larger screens */
          font-size: 16px;
        }
        .button {
          background-color: #cdf5c1;
          border: 1px solid #57de2f;
          border-radius: 10px;
          padding: 20px;
          margin: 5px;
          cursor: pointer;
          color: #4a4f4a;
          font-family: verdana, fantasy;
          width: 180px; /* Fixed width */
          height: 60px; /* Fixed height */
          display: flex;
          align-items: center;
          justify-content: center;
          box-sizing: border-box;
        }
        .button:hover {
          background-color: #4CAF50;
          color: #000000;
        }
        .modal {
          display: none;
          position: fixed;
          z-index: 1;
          left: 0;
          top: 0;
          width: 100%;
          height: 100%;
          overflow: auto;
          background-color: rgba(0, 0, 0, 0.4);
        }
        .modal-content {
          background-color: #fefefe;
          margin: 15% auto;
          padding: 20px;
          border: 1px solid #888;
          width: 80%;
        }
        .close {
          color: #aaa;
          float: right;
          font-size: 28px;
          font-weight: bold;
        }
        .close:hover,
        .close:focus {
          color: black;
          text-decoration: none;
          cursor: pointer;
        }
        /* Media Queries for responsive gap */
        @media (max-width: 1200px) {
          .button-row {
            gap: 20px; /* Smaller gap for medium screens */
          }
        }
        @media (max-width: 768px) {
          .button-row {
            gap: 15px; /* Smaller gap for tablet screens */
          }
        }
        @media (max-width: 480px) {
          .button-row {
            gap: 10px; /* Smaller gap for mobile screens */
          }
        }
      </style>
      <div class="buttons-container">
        <div class="button-row">
          ${buttons
            .slice(0, 4)
            .map(
              (button, index) => `
            <div class="button" data-index="${index}" data-src="${button.src}">
              ${button.label}
            </div>
            <div id="modal-${index}" class="modal">
              <div class="modal-content">
                <span class="close" data-index="${index}">&times;</span>
                <div class="modal-body"></div>
              </div>
            </div>
          `
            )
            .join("")}
        </div>
        <div class="button-row">
          ${buttons
            .slice(4)
            .map(
              (button, index) => `
            <div class="button" data-index="${index + 4}" data-src="${button.src}">
              ${button.label}
            </div>
            <div id="modal-${index + 4}" class="modal">
              <div class="modal-content">
                <span class="close" data-index="${index + 4}">&times;</span>
                <div class="modal-body"></div>
              </div>
            </div>
          `
            )
            .join("")}
        </div>
      </div>
    `;

    this.addEventListeners();
  }

  addEventListeners() {
    const buttons = this.shadowRoot.querySelectorAll(".button");
    const modals = this.shadowRoot.querySelectorAll(".modal");
    const closes = this.shadowRoot.querySelectorAll(".close");

    buttons.forEach((button) => {
      button.addEventListener("click", (e) => {
        const index = e.target.getAttribute("data-index");
        const src = e.target.getAttribute("data-src");
        const modal = this.shadowRoot.getElementById(`modal-${index}`);
        const modalBody = modal.querySelector(".modal-body");

        // Load the external HTML content
        fetch(src)
          .then((response) => response.text())
          .then((data) => {
            modalBody.innerHTML = data;
            modal.style.display = "block";
          });
      });
    });

    closes.forEach((close) => {
      close.addEventListener("click", (e) => {
        const index = e.target.getAttribute("data-index");
        this.shadowRoot.getElementById(`modal-${index}`).style.display = "none";
      });
    });

    window.addEventListener("click", (e) => {
      modals.forEach((modal) => {
        const modalContent = modal.querySelector(".modal-content");
        if (e.target === modal) {
          modal.style.display = "none";
        }
      });
    });

    modals.forEach((modal) => {
      modal.addEventListener("click", (e) => {
        const modalContent = modal.querySelector(".modal-content");
        if (!modalContent.contains(e.target)) {
          modal.style.display = "none";
        }
      });
    });
  }
}

customElements.define("intro-modal-button", IntroModalButton);

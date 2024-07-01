class MainHeader extends HTMLElement {
  constructor() {
    super(); // 항상 최상위 생성자 호출 필수
    this.attachShadow({ mode: "open" }); // Shadow DOM
  }

  connectedCallback() {
    this.shadowRoot.innerHTML = `
      <style>
        .header-container {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 10px;
          background-color: #ffffff;
          border-bottom: 1px solid #e0e0e0;
          margin-left: 20px;
          margin-right: 20px;
          font-family: verdana, fantasy;
        }
        h1 {
          margin: 0;
        }
        .home-link {
          text-decoration: none;
          color: #4CAF50;
          font-size: 24px;
        }
        .home-link:hover {
          text-decoration: none;
        }
      </style>
      <div class="header-container">
        <a href="${this.getAttribute("home-link")}" class="home-link"><h1>${this.getAttribute(
      "title"
    )}</h1></a>
        <a href="${this.getAttribute("github-link")}" target="_blank">
          <img src="${this.getAttribute("image-src")}" alt="GitHub Link">
        </a>
      </div>
    `;
  }
}

customElements.define("main-header", MainHeader);

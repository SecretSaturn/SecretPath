import './style.css'
import { setupConnect } from './connect'
import { setupSubmit } from './submit'

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
<header>
  <h1>Fortress Labs</h1>
  <div id="links">
    <a href="">
    <div class="card">
      Whitepaper
    </div>
    </a>
    <a href="">
    <div class="card">
      GitHub
    </div>
    </a>
    <a href="">
    <div class="card">
      Docs
    </div>
    </a>
  </div>
</header>
  <div>
    <h2>Sample Application: Privacy-Preserving On-chain Credit Scoring</h2>
    <div id="form">
      <form name="inputForm">
      <label for="input1">$USD value of offchain assets:  </label>
      <input type="number" placeholder="$" id="input1" name="input1" />
      <br>
      <label for="input2">$USD value of onchain assets:  </label>
      <input type="text" placeholder="$" id="input2" name="input2" />
      <br>
      <label for="input3">$USD value of liabilities (loans, mortgages):  </label>
      <input type="text" placeholder="$" id="input3" name="input3" />
      <br>
      <label for="input4">$USD value of loan payments missed in last 5 years:  </label>
      <input type="text" placeholder="$" id="input4" name="input4" />
      <br>
      <label for="input5">$USD value of salary/income stream:  </label>
      <input type="text" placeholder="$" id="input5" name="input5" />
        <br>
      <button id="submit">Submit</button>

    </div>
    <div id="preview" style="word-wrap: break-word;">
    </div>
    <div class="card">
    </div>
  </div>
`
setupSubmit(document.querySelector<HTMLButtonElement>('#submit')!)
setupConnect(document.querySelector<HTMLButtonElement>('#connect')!)
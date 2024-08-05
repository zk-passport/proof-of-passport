/** @jsxImportSource frog/jsx */

import { Button, Frog, TextInput } from "frog";
import { devtools } from "frog/dev";
// import { neynar } from 'frog/hubs'
import { handle } from "frog/next";
import { serveStatic } from "frog/serve-static";
import abi from "./abi.json";
import { ethers } from "ethers";
const sbtToken = "0xaaE6e64374a644C91A209969261F61A52e0F7428";
const app = new Frog({
  assetsPath: "/",
  basePath: "/api",
  // Supply a Hub to enable frame verification.
  // hub: neynar({ apiKey: 'NEYNAR_FROG_FM' })
  title: "Frog Frame",
});

// Uncomment to use Edge Runtime
// export const runtime = 'edge'

app.frame("/", (c) => {
  const { buttonValue, inputText, status } = c;
  const input = inputText || buttonValue;
  // const address = c.;
  return c.res({
    action: "/balance",
    image: (
      // <div tw="bg-gray-100 flex items-center justify-center min-h-screen">
      <div tw="flex flex-col w-full h-full items-center justify-center bg-white">
        <div tw="w-full bg-white p-4 flex">
          <div tw="max-w-7xl mx-auto flex items-center">
            <h1 tw="text-2xl font-bold text-gray-900">Proof of Passport</h1>
          </div>
        </div>
        <div tw="bg-gray-50 flex w-full">
          <div tw="flex flex-col md:flex-row w-full py-12 px-4 md:items-center justify-between p-8">
            <div tw="flex flex-1 flex-col bg-blue-100 p-6 rounded-lg text-center shadow-md m-4">
              <h2 tw="text-3xl sm:text-4xl font-bold tracking-tight text-gray-900">
                1. Scan your passport
              </h2>
              <p tw="mt-2 text-base font-medium text-gray-700">
                Scan your passport using the NFC reader of your phone.
              </p>
            </div>
            <div tw="flex flex-1 flex-col bg-blue-100 p-6 rounded-lg text-center shadow-md m-4">
              <h2 tw="text-3xl sm:text-4xl font-bold tracking-tight text-gray-900">
                2. Generate your proof
              </h2>
              <p tw="mt-2 text-base font-medium text-gray-700">
                Generate a zk proof over your passport, selecting only what you
                want to disclose.
              </p>
            </div>
            <div tw="flex flex-1 flex-col bg-blue-100 p-6 rounded-lg text-center shadow-md m-4">
              <h2 tw="text-3xl sm:text-4xl font-bold tracking-tight text-gray-900">
                3. Be Verified
              </h2>
              <p tw="mt-2 text-base font-medium text-gray-700">
                Share your zk proof with selected applications...
              </p>
            </div>
          </div>
        </div>
      </div>
      // </div>
    ),
    intents: [
      <TextInput placeholder="User Address" />,
      <Button.Link href="https://testflight.apple.com/join/WfZnZWfn">
        Download App
      </Button.Link>,
      <Button value={inputText}>Verify Mint</Button>,
    ],
  });
});

async function name(buttonValue: string) {
  try {
    const network = new ethers.Network("sepolia", 11155111);
    const provider = new ethers.JsonRpcProvider(
      "https://11155111.rpc.thirdweb.com",
      network,
      { staticNetwork: true }
    ); // Use the appropriate RPC URL

    const contract = new ethers.Contract(sbtToken, abi, provider);
    // console.log(contract)
    const data = await contract.balanceOf(buttonValue);
    // console.log(data)
    const balance = parseInt(data, 10).toString();
    console.log(balance);
    return balance;
  } catch (error) {
    console.log(error);
  }
}

app.frame("/balance", async (c) => {
  // console.log(c)
  const { buttonValue, inputText } = c;

  try {
    // Await the result of the asynchronous function
    const val = await name(inputText as string);
    console.log(typeof val)
    if (typeof val === "string") {
      const numericValue = parseInt(val, 10);
      const isValidNumber = !isNaN(numericValue);
      console.log(numericValue, isValidNumber);
      console.log("Balance:", val, "Input Text:", inputText);
      return c.res({
        action: "/",
        image: (
          <div style={{ color: "blue", display: "flex", fontSize: 60 }}>
            {isValidNumber && numericValue > 0
              ? "verified user"
              : "unverified user"}
          </div>
        ),
        intents: [
          <Button.Link href="https://testflight.apple.com/join/WfZnZWfn">
            Download App
          </Button.Link>,
          <Button>Home</Button>,
        ],
      });
    }
    // Return the response after the async operation is complete
    return c.res({
      action: "/",
      image: (
        <div style={{ color: "blue", display: "flex", fontSize: 60 }}>
          Network Error!
        </div>
      ),
      intents: [
        <Button.Link href="https://testflight.apple.com/join/WfZnZWfn">
          Download App
        </Button.Link>,
        <Button>Home</Button>,
      ],
    });
  } catch (error) {
    console.error("Error retrieving balance:", (error as Error).message);
    return c.res({
      action: "/",
      image: (
        <div style={{ color: "red", display: "flex", fontSize: 60 }}>
          Error retrieving balance for {inputText}
        </div>
      ),
      intents: [
        <Button.Link href="https://testflight.apple.com/join/WfZnZWfn">
          Download App
        </Button.Link>,
        <Button>Home</Button>,
      ],
    });
  }
});
// app.transaction('/balance', (c) => {
//   const { inputText, address } = c

//   // Contract transaction response.
//   const val = c.contract({
//     abi,
//     chainId: 'eip155:11155111',
//     functionName: 'balanceOf',
//     args: [address],
//     to: '0x4873528341D33Ec918c7465F244491aCB75Bc95F'
//   })
//   // alert(ans.data)
//   console.log(val.data)error
//   return val

// })

devtools(app, { serveStatic });

export const GET = handle(app);
export const POST = handle(app);

// NOTE: That if you are using the devtools and enable Edge Runtime, you will need to copy the devtools
// static assets to the public folder. You can do this by adding a script to your package.json:
// ```json
// {
//   scripts: {
//     "copy-static": "cp -r ./node_modules/frog/_lib/ui/.frog ./public/.frog"
//   }
// }
// ```
// Next, you'll want to set up the devtools to use the correct assets path:
// ```ts
// devtools(app, { assetsPath: '/.frog' })
// ```

from fastapi import Request
from fastapi.responses import PlainTextResponse
from modal import Image, Mount, App, web_endpoint
import subprocess
import asyncio
import json
import hashlib

# Define the image with bash, nodejs, npm, and snarkjs, and ensure using a compatible Node.js version
image = Image.debian_slim().apt_install("bash", "curl").run_commands(
    "curl -fsSL https://deb.nodesource.com/setup_16.x | bash -",
    "apt-get install -y nodejs",
    "npm install -g snarkjs"
)

# Create the app
app = App(image=image)

# Mount the local directory containing the script and necessary files
mount = Mount.from_local_dir("src", remote_path="/root/src")

# Define the function to execute the script and capture the logs
@app.function(mounts=[mount], cpu=14)
@web_endpoint(method="POST")
async def run_script(request: Request):
    # Read the JSON data from the request body
    data = await request.json()
    # Convert JSON data to a properly formatted string
    json_data = json.dumps(data)

    # Compute the hash of the input data
    hash_object = hashlib.sha256(json_data.encode())
    hash_hex = hash_object.hexdigest()

    # Run the script and pass the JSON data to it asynchronously
    process = await asyncio.create_subprocess_exec(
        "/bin/bash", "/root/src/prove.sh",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate(input=json_data.encode())

    # Log detailed error message if any
    if process.returncode != 0:
        error_message = f"Error: {stderr.decode()}\n"
        error_message += f"Standard Output: {stdout.decode()}"
        return PlainTextResponse(error_message, status_code=500)

    # Return the content of the unique proof and public files
    try:
        with open(f"/root/src/data/{hash_hex}/proof.json", "r") as proof_file:
            proof_content = proof_file.read()
        with open(f"/root/src/data/{hash_hex}/public.json", "r") as public_file:
            public_content = public_file.read()
        response_data = {
            "proof": json.loads(proof_content),
            "public": json.loads(public_content)
        }
        return PlainTextResponse(json.dumps(response_data), media_type="application/json")
    except FileNotFoundError:
        return PlainTextResponse("Error: proof.json or public.json not found", status_code=500)

# Run the app
if __name__ == "__main__":
    app.run()
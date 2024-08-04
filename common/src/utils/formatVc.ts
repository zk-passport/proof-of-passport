//Import the v4 function from the uuid package to generate unique identifiers
import {v4 as uuidv4} from 'uuid';
//Exports the formatAsVC function that takes a credentialSubject object as a parameter
export function formatAsVC(credentialSubject: object){
//Returns an object representing a Verifiable Credential (VC) conforming to the W3C standard   
    return {
//@context specifies the JSON-LD context used for the credential     
        "@context": [
              "https://www.w3.org/2018/credentials/v1"
        ],
       
        "type":["VerifiableCredential"], 
        "id": `urn:uuid:${uuidv4()}`, 
        "issuer": "https://issuer.example.com", 
        "issuanceDate": new Date().toISOString(),
        "creendtialSubject": credentialSubject 
    };
}
//type defines the type of credential, in this case it is a "VerifiableCredential"
//id assigns a unique identifier to the credential using a v4 UUID
//issuer specifies the issuer of the credential, here is an example URL
//issuanceDate indicates the date and time of issuance of the credential in ISO 8601 format
//credentialSubject contains the specific information about the credential subject

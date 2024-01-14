
//  Prover.swift
//  ProofOfPassport

//  Created by Florent on 13/01/2024.


import Foundation
import React
import Security
import MoproKit

@available(iOS 15, *)
@objc(Prover)
class Prover: NSObject {

  let moproCircom = MoproKit.MoproCircom()
  var generatedProof: Data?
  var publicInputs: Data?

  @objc(runInitAction:reject:)
  func runInitAction(resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {    // Update the textView on the main thread
    print("Initializing library")

    // Execute long-running tasks in the background
    DispatchQueue.global(qos: .userInitiated).async {
      // Record start time
      let start = CFAbsoluteTimeGetCurrent()

      do {
        try initializeMopro()

        // Record end time and compute duration
        let end = CFAbsoluteTimeGetCurrent()
        let timeTaken = end - start

        // Log the time taken for initialization
        print("Initializing arkzkey took \(timeTaken) seconds.")
      } catch {
        // Log any errors that occurred during initialization
        print("An error occurred during initialization: \(error)")
      }
    }
  }

  @objc(runProveAction:reject:)
  func runProveAction(resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    // Logic for prove (generate_proof2)
    do {
      // Prepare inputs
      let signature: [String] = [
        "3582320600048169363",
        "7163546589759624213",
        "18262551396327275695",
        "4479772254206047016",
        "1970274621151677644",
        "6547632513799968987",
        "921117808165172908",
        "7155116889028933260",
        "16769940396381196125",
        "17141182191056257954",
        "4376997046052607007",
        "17471823348423771450",
        "16282311012391954891",
        "70286524413490741",
        "1588836847166444745",
        "15693430141227594668",
        "13832254169115286697",
        "15936550641925323613",
        "323842208142565220",
        "6558662646882345749",
        "15268061661646212265",
        "14962976685717212593",
        "15773505053543368901",
        "9586594741348111792",
        "1455720481014374292",
        "13945813312010515080",
        "6352059456732816887",
        "17556873002865047035",
        "2412591065060484384",
        "11512123092407778330",
        "8499281165724578877",
        "12768005853882726493",
      ]

      let modulus: [String] = [
        "13792647154200341559",
        "12773492180790982043",
        "13046321649363433702",
        "10174370803876824128",
        "7282572246071034406",
        "1524365412687682781",
        "4900829043004737418",
        "6195884386932410966",
        "13554217876979843574",
        "17902692039595931737",
        "12433028734895890975",
        "15971442058448435996",
        "4591894758077129763",
        "11258250015882429548",
        "16399550288873254981",
        "8246389845141771315",
        "14040203746442788850",
        "7283856864330834987",
        "12297563098718697441",
        "13560928146585163504",
        "7380926829734048483",
        "14591299561622291080",
        "8439722381984777599",
        "17375431987296514829",
        "16727607878674407272",
        "3233954801381564296",
        "17255435698225160983",
        "15093748890170255670",
        "15810389980847260072",
        "11120056430439037392",
        "5866130971823719482",
        "13327552690270163501",
      ]

      let base_message: [String] = ["18114495772705111902", "2254271930739856077",
        "2068851770", "0","0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0","0", "0", "0","0",
      ]

      var inputs = [String: [String]]()
      inputs["signature"] = signature;
      inputs["modulus"] = modulus;
      inputs["base_message"] = base_message;

      let start = CFAbsoluteTimeGetCurrent()

      // Generate Proof
      let generateProofResult = try generateProof2(circuitInputs: inputs)
      assert(!generateProofResult.proof.isEmpty, "Proof should not be empty")

      // Record end time and compute duration
      let end = CFAbsoluteTimeGetCurrent()
      let timeTaken = end - start

      // Store the generated proof and public inputs for later verification
      generatedProof = generateProofResult.proof
      publicInputs = generateProofResult.inputs

      print("Proof generation took \(timeTaken) seconds.")
    } catch let error as MoproError {
      print("MoproError: \(error)")
    } catch {
      print("Unexpected error: \(error)")
    }
  }

  @objc(runVerifyAction:reject:)
  func runVerifyAction(resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    // Logic for verify
    guard let proof = generatedProof,
      let publicInputs = publicInputs else {
      print("Proof has not been generated yet.")
      return
    }
    do {
      // Verify Proof
      let isValid = try verifyProof2(proof: proof, publicInput: publicInputs)
      assert(isValid, "Proof verification should succeed")

      print("Proof verification succeeded.")
    } catch let error as MoproError {
      print("MoproError: \(error)")  
    } catch {
      print("Unexpected error: \(error)")
    }
  }
}

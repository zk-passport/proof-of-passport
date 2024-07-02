pragma circom  2.1.6;

include "../utils/isValid.circom";

template IsValid_tester() {

    signal input currDate[6];
    signal input validityDateASCII[6];
    
    component isValid = IsValid();
    isValid.currDate <== currDate;
    isValid.validityDateASCII <== validityDateASCII;

    signal output out <== isValid.out;
}

component main = IsValid_tester();

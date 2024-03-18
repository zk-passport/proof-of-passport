// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 2093718139832935465124180037514503443201478091541963164486272055771790404921;
    uint256 constant deltax2 = 20585442054828778086754089553076940532182174379144545099624881205809396207383;
    uint256 constant deltay1 = 6558312073524779650437504502979304998508354498340059354134513060253470940564;
    uint256 constant deltay2 = 5659674037499045144131342905049155939834201376362906403068446335083953572736;

    
    uint256 constant IC0x = 12358371560351339950261746817829615662864648250224246579760823479801160726966;
    uint256 constant IC0y = 8941502525560997533107244888678697046415829976829277437144304248888506926598;
    
    uint256 constant IC1x = 3392609077893666393818373788632729347394100296009683175444785824084696943023;
    uint256 constant IC1y = 15778475214327229583146197018054931792117795500362679219822006631962765425084;
    
    uint256 constant IC2x = 8099776627791518876029724839541619668524168243683543215181264127561560866378;
    uint256 constant IC2y = 13957298841388220900071014236692228557278984690959800731798739560589103260217;
    
    uint256 constant IC3x = 6867144446394518543541509416020662846352658926638580312202993008656043735722;
    uint256 constant IC3y = 20361100619082527644543330176105343018113961431298631122109940433281427191335;
    
    uint256 constant IC4x = 7820262163570764148713607342549403510616534732388680563758448525457856266041;
    uint256 constant IC4y = 17427646703250487254100654670394303917427848369600540774960876444848655648790;
    
    uint256 constant IC5x = 9329038096752685892195458886791344390985266132226910745197610004790817081243;
    uint256 constant IC5y = 17633606162637893141834852474543311873554106055343324203721189043258518542986;
    
    uint256 constant IC6x = 15214972039132546074990559591905856279100817712638264680172391278670552836943;
    uint256 constant IC6y = 17793931839829884897490767708362461073405286327564854852321755412397701882051;
    
    uint256 constant IC7x = 16432451118675554466944501175190419802495200895264935959505007091630391748307;
    uint256 constant IC7y = 17005455758161268740259966336931374444292463497649856761950776907003856006158;
    
    uint256 constant IC8x = 16566084605942179954484095659462642108428050412914361949529099255053163336577;
    uint256 constant IC8y = 11348847474900901532074632045897840328394652876808508608277201509162617389226;
    
    uint256 constant IC9x = 20432721442439987594811029579638507905558963238303258423962968887055079318014;
    uint256 constant IC9y = 17630633329984044021525868813160201090283137867464472918574994399246772391534;
    
    uint256 constant IC10x = 5699789224797518651982187895765852840229524263129270266806855312076243175369;
    uint256 constant IC10y = 5575685047942777136027938128867511021185787087783710620156009601989720400423;
    
    uint256 constant IC11x = 7474962396815226656505783226184398885932429996968198991602177469258624227676;
    uint256 constant IC11y = 13295953383787032296147156727696765949284856824641801644998677571719156809710;
    
    uint256 constant IC12x = 7125408302133541426096601033611287561635809191011183803473287615455611004055;
    uint256 constant IC12y = 2993824677580561931899725088290448751828842746446863028131844542431810217534;
    
    uint256 constant IC13x = 13104153687587252960029187345356816832922284531311953051216743085545221973160;
    uint256 constant IC13y = 7405322578735061472878628039827056816271101505201175316717177556683750653196;
    
    uint256 constant IC14x = 9070340003155622806917979397122180030817945108774043344801622013416220642839;
    uint256 constant IC14y = 6448142239834215464348644080211718417532770711627875088279288533854718074854;
    
    uint256 constant IC15x = 19115296167742895190557430003566978073320550923055046533289349069129250085692;
    uint256 constant IC15y = 14023194747126190791090505626051096268998429680184461960003071238543625728369;
    
    uint256 constant IC16x = 3205179961068657974791317429435230052576637598837700853958154288779815988964;
    uint256 constant IC16y = 13962036792812653197816813268344534136187601501933782827315669353329176964877;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[16] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }

import { groth16 } from 'snarkjs';
import { attributeToPosition, countryCodes, DEFAULT_RPC_URL, PASSPORT_ATTESTATION_ID } from './common/src/constants/constants';
import { checkMerkleRoot, getCurrentDateFormatted, parsePublicSignals, unpackReveal } from './utils';
import { ProofOfPassportVerifierReport } from './ProofOfPassportVerifierReport';

const MOCK_MERKLE_ROOT_CHECK = false;

export class ProofOfPassportWeb2Verifier {
    scope: string;
    attestationId: string;
    requirements: Array<[string, number | string]>;
    rpcUrl: string;
    report: ProofOfPassportVerifierReport;

    constructor(options: { scope: string, attestationId?: string, requirements?: Array<[string, number | string]>, rpcUrl?: string }) {
        this.scope = options.scope;
        this.attestationId = options.attestationId || PASSPORT_ATTESTATION_ID;
        this.requirements = options.requirements || [];
        this.rpcUrl = options.rpcUrl || DEFAULT_RPC_URL;
        this.report = new ProofOfPassportVerifierReport();
    }

    async verify(proofOfPassportWeb2Inputs: ProofOfPassportWeb2Inputs): Promise<ProofOfPassportVerifierReport> {
        const parsedPublicSignals = parsePublicSignals(proofOfPassportWeb2Inputs.publicSignals);
        //1. Verify the scope
        if (parsedPublicSignals.scope !== this.scope) {
            this.report.exposeAttribute('scope');
        }
        console.log('\x1b[32m%s\x1b[0m', `- scope verified`);

        //2. Verify the merkle_root
        const merkleRootIsValid = await checkMerkleRoot(this.rpcUrl, parsedPublicSignals.merkle_root);
        if (!(merkleRootIsValid || MOCK_MERKLE_ROOT_CHECK)) {
            this.report.exposeAttribute('merkle_root');
        }
        console.log('\x1b[32m%s\x1b[0m', `- merkle_root verified`);

        //3. Verify the attestation_id
        if (parsedPublicSignals.attestation_id !== this.attestationId) {
            this.report.exposeAttribute('attestation_id');
        }
        console.log('\x1b[32m%s\x1b[0m', `- attestation_id verified`);

        //4. Verify the current_date
        if (parsedPublicSignals.current_date.toString() !== getCurrentDateFormatted().toString()) {
            this.report.exposeAttribute('current_date');
        }
        console.log('\x1b[32m%s\x1b[0m', `- current_date verified`);

        //5. Verify requirements
        const unpackedReveal = unpackReveal(parsedPublicSignals.revealedData_packed);
        for (const requirement of this.requirements) {
            const attribute = requirement[0];
            const value = requirement[1];
            const position = attributeToPosition[attribute];
            let attributeValue = '';
            for (let i = position[0]; i <= position[1]; i++) {
                attributeValue += unpackedReveal[i];
            }
            if (requirement[0] === "nationality" || requirement[0] === "issuing_state") {
                if (!countryCodes[attributeValue] || countryCodes[attributeValue] !== value) {
                    this.report.exposeAttribute(attribute as keyof ProofOfPassportVerifierReport);
                }
            }
            else {
                if (attributeValue !== value) {
                    this.report.exposeAttribute(attribute as keyof ProofOfPassportVerifierReport);
                }
            }
            console.log('\x1b[32m%s\x1b[0m', `- requirement ${requirement[0]} verified`);

        }

        //6. Verify the proof
        const vkey_disclose = {
            "protocol": "groth16",
            "curve": "bn128",
            "nPublic": 14,
            "vk_alpha_1": [
                "20491192805390485299153009773594534940189261866228447918068658471970481763042",
                "9383485363053290200918347156157836566562967994039712273449902621266178545958",
                "1"
            ],
            "vk_beta_2": [
                [
                    "6375614351688725206403948262868962793625744043794305715222011528459656738731",
                    "4252822878758300859123897981450591353533073413197771768651442665752259397132"
                ],
                [
                    "10505242626370262277552901082094356697409835680220590971873171140371331206856",
                    "21847035105528745403288232691147584728191162732299865338377159692350059136679"
                ],
                [
                    "1",
                    "0"
                ]
            ],
            "vk_gamma_2": [
                [
                    "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                    "11559732032986387107991004021392285783925812861821192530917403151452391805634"
                ],
                [
                    "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                    "4082367875863433681332203403145435568316851327593401208105741076214120093531"
                ],
                [
                    "1",
                    "0"
                ]
            ],
            "vk_delta_2": [
                [
                    "6942436740229168666595536581519256291593117600832247164924519038970269461046",
                    "17557865657217054151399710026819127874171362865266657132072043760282335721027"
                ],
                [
                    "15629082942757783052734933529055204330846116501031658743204188522840567440030",
                    "866803245463331646327183913175583329159450203348438102150009828684148559895"
                ],
                [
                    "1",
                    "0"
                ]
            ],
            "vk_alphabeta_12": [
                [
                    [
                        "2029413683389138792403550203267699914886160938906632433982220835551125967885",
                        "21072700047562757817161031222997517981543347628379360635925549008442030252106"
                    ],
                    [
                        "5940354580057074848093997050200682056184807770593307860589430076672439820312",
                        "12156638873931618554171829126792193045421052652279363021382169897324752428276"
                    ],
                    [
                        "7898200236362823042373859371574133993780991612861777490112507062703164551277",
                        "7074218545237549455313236346927434013100842096812539264420499035217050630853"
                    ]
                ],
                [
                    [
                        "7077479683546002997211712695946002074877511277312570035766170199895071832130",
                        "10093483419865920389913245021038182291233451549023025229112148274109565435465"
                    ],
                    [
                        "4595479056700221319381530156280926371456704509942304414423590385166031118820",
                        "19831328484489333784475432780421641293929726139240675179672856274388269393268"
                    ],
                    [
                        "11934129596455521040620786944827826205713621633706285934057045369193958244500",
                        "8037395052364110730298837004334506829870972346962140206007064471173334027475"
                    ]
                ]
            ],
            "IC": [
                [
                    "10998553002727424987884583305349753345629818748955483305954960876370686844925",
                    "18369020735737057562107768810182682586161750799521907185011795199521493953276",
                    "1"
                ],
                [
                    "3870156317905136354369536369223776179854927352937539086581682263147147725326",
                    "947908099816727525943796981035826395896386995128918341433720280874486019589",
                    "1"
                ],
                [
                    "9619614659642762666110070745787072277198407288262286655564043642023793950605",
                    "1444870940646607538213811271690623291794427513321591343855928143309974143815",
                    "1"
                ],
                [
                    "10290556281387838061211784545032614883237381276187632418810139452226710406378",
                    "12820288689147023950592422696432066467590193138126598372596214785570201388663",
                    "1"
                ],
                [
                    "10044189939644279332588298610988772483187101321076758071894028734198440253205",
                    "15016612240779620571490237444430121691511928826472608688773111463692886510804",
                    "1"
                ],
                [
                    "6158786594227478832634691320618082224218218524296943509099128649963428556955",
                    "2818896662082406397657145229256654653904841140122301210666395782176903475916",
                    "1"
                ],
                [
                    "200295911748915977788397688942615122670319721182540082686195028815964792730",
                    "16374098866162622474777608838325780437892472095191094825634065695603492498672",
                    "1"
                ],
                [
                    "1001933084599581827076405562561115761770358156189382784432273793509010836288",
                    "13618159500648302749264797924828312592779374840705268445533823753672345860949",
                    "1"
                ],
                [
                    "12152127135355257668073159516593687751413730484411437719952408933610175077761",
                    "15590965974244077225547659000022179448961631917634079092877797469009672737373",
                    "1"
                ],
                [
                    "14643873766083688335082369233094018379987105460165787549629338089338629672719",
                    "18976194036990056092890684065171543382286602242265347684324001010669281606450",
                    "1"
                ],
                [
                    "4974359282562923295097396773583362835614429754286473873410152881834388935350",
                    "2615967425575591157936435871031665935046196308487298765704452331348089292330",
                    "1"
                ],
                [
                    "16489750714044704248135942822786071904168862423655325973193848507501139487825",
                    "4644993658884496411511912365771411317040070112230395754480725062427812526601",
                    "1"
                ],
                [
                    "11801682757910657983396995619983996921870874978799260563404809167285348391422",
                    "19228652101325919244735412842681375925619382430642205708320466729501949572254",
                    "1"
                ],
                [
                    "4495248066509783309072792039672520701419947625749866524660708846549914823847",
                    "4585216314173588273427806971446529726371555267351812069737927114283850919560",
                    "1"
                ],
                [
                    "18719866673490039760627957665040843673978402675108669037278157044178865894074",
                    "11183065716352601580915387671262116390467334689778841393328736869598818253587",
                    "1"
                ]
            ]
        };
        console.log(vkey_disclose);
        console.log("publicSignals", proofOfPassportWeb2Inputs.publicSignals);
        console.log("proof", proofOfPassportWeb2Inputs.proof);
        const verified_disclose = await groth16.verify(
            vkey_disclose,
            proofOfPassportWeb2Inputs.publicSignals,
            proofOfPassportWeb2Inputs.proof as any
        )
        if (!verified_disclose) {
            this.report.exposeAttribute('proof');
        }
        console.log('\x1b[32m%s\x1b[0m', `- proof verified`);

        this.report.nullifier = parsedPublicSignals.nullifier;
        this.report.user_identifier = parsedPublicSignals.user_identifier;

        return this.report;
    }
}

export class ProofOfPassportWeb2Inputs {
    publicSignals: string[];
    proof: string[];

    constructor(publicSignals: string[], proof: string[]) {
        this.publicSignals = publicSignals;
        this.proof = proof;
    }
}

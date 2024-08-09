# How we Process Ofac Lists :

## Data Collection : 
- We collect the data from the official website of the U.S. Department of the Treasury's Office of Foreign Assets Control (OFAC) and download the data in the form of a CSV file from [here](https://sanctionslist.ofac.treas.gov/Home/SdnList)

- The SDN list contains the names of individuals, entities and groups designated by OFAC as well as the listing of maritime vessels and aircraft that are blocked by OFAC.

### ofacdata/original
- The data is stored in the form of 2 CSV files named `sdn.csv` and `add.csv`. `dataspec.txt` explains the data specification for the CSV data files.
- The data is cleaned to obtain the required information for individuals from sdn.csv file.
A ballpark number of 6917 individuals (at the time of writing this document) entries are present in sdn.csv. Remaining entries are entities, vessels, and aircrafts. 

## Data Processing :

### ofacdata/scripts
- The `ofac.ipynb` script extracts the data from both the csv's and parses them in json fommat. 
- We parse all ethereum addresses, regardless of individual or entity in eth_addresses.json.
- For individuals, we parse : 
    - full name (first name, last name), dob(day, month, year) in names.json
    - passports and passport issuing country in passport.json
- The jsons are stored at ofacdata/inputes to be used furthur by SMT's.

## Data Usage :
These jsons are later used to create sparse merkle trees for non-membership proofs. We provide 3 levels of proofs.
- Match through Passport Number  : level 3 (Absolute Match)
- Match through Names and Dob combo tree : level 2 (High Probability Match)
- Match only through Names : level 1 (Partial Match)
The merkle tree is also exported as json in ofacdata/outputs for time constraint export and import.

Check out src/ofacTree.ts for more details.<br>

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Formatter is Ownable {
    mapping(string => string) private countryCodes;

    constructor() {
        transferOwnership(msg.sender);
    }

    function formatName(string memory input) public pure returns (string memory firstName, string memory lastName) {
        bytes memory inputBytes = bytes(input);
        bytes memory firstNameBytes;
        bytes memory lastNameBytes;

        uint i = 0;
        // Extract last name
        while(i < inputBytes.length && inputBytes[i] != '<') {
            lastNameBytes = abi.encodePacked(lastNameBytes, inputBytes[i]);
            i++;
        }

        // Skip the separator "<<"
        i += 2;

        // Extract first names
        while(i < inputBytes.length) {
            if(inputBytes[i] == '<') {
                if (i + 1 < inputBytes.length && inputBytes[i + 1] == '<') {
                    break;
                }
                firstNameBytes = abi.encodePacked(firstNameBytes, ' ');
            } else {
                firstNameBytes = abi.encodePacked(firstNameBytes, inputBytes[i]);
            }
            i++;
        }

        firstName = string(firstNameBytes);
        lastName = string(lastNameBytes);
    }

	function formatDate(string memory date) public pure returns (string memory) {
		// Ensure the date string is the correct length
		require(bytes(date).length == 6, "Invalid date length");

		string memory year = substring(date, 0, 2);
		string memory month = substring(date, 2, 4);
		string memory day = substring(date, 4, 6);

		return string(abi.encodePacked(day, "-", month, "-", year));
	}

	function substring(string memory str, uint startIndex, uint endIndex) public pure returns (string memory) {
		bytes memory strBytes = bytes(str);
		bytes memory result = new bytes(endIndex - startIndex);

		for(uint i = startIndex; i < endIndex; i++) {
			result[i - startIndex] = strBytes[i];
		}

		return string(result);
	}

    function formatCountryName(string memory code) public view returns (string memory) {
        string memory countryName = countryCodes[code];
        if(bytes(countryName).length == 0) {
            return code;
        }
        return countryName;
    }

    function addCountryCodes(string[][] memory codeToName) public onlyOwner {
        for(uint i = 0; i < codeToName.length; i++) {
            string memory code = codeToName[i][0];
            string memory name = codeToName[i][1];
            countryCodes[code] = name;
        }
    }

    function dateToUnixTimestamp(string memory date) public pure returns (uint256) {
        // Ensure the date string is the correct length (6 characters)
        require(bytes(date).length == 6, "Invalid date length");

        // Extract day, month, and year
        uint year = parseDatePart(substring(date, 0, 2)) + 2000;
        uint month = parseDatePart(substring(date, 2, 4));
        uint day = parseDatePart(substring(date, 4, 6));

        // Convert to Unix timestamp
        return toTimestamp(year, month, day);
    }

    // Helper function to convert a string to an integer
    function parseDatePart(string memory value) internal pure returns (uint) {
        bytes memory tempEmptyStringTest = bytes(value);
        if (tempEmptyStringTest.length == 0) {
            return 0;
        }

        uint digit;
        uint result;
        for (uint i = 0; i < tempEmptyStringTest.length; i++) {
            digit = uint(uint8(tempEmptyStringTest[i])) - 48; // '0' is 48 in ASCII
            result = result * 10 + digit;
        }
        return result;
    }

    // Convert date to Unix timestamp
    function toTimestamp(uint256 year, uint256 month, uint256 day) internal pure returns (uint timestamp) {
        uint16 i;

        // Year
        for (i = 1970; i < year; i++) {
            if (isLeapYear(i)) {
                timestamp += 366 days;
            } else {
                timestamp += 365 days;
            }
        }

        // Month
        uint8[12] memory monthDayCounts;
        monthDayCounts[0] = 31;
        if (isLeapYear(year)) {
            monthDayCounts[1] = 29;
        } else {
            monthDayCounts[1] = 28;
        }
        monthDayCounts[2] = 31;
        monthDayCounts[3] = 30;
        monthDayCounts[4] = 31;
        monthDayCounts[5] = 30;
        monthDayCounts[6] = 31;
        monthDayCounts[7] = 31;
        monthDayCounts[8] = 30;
        monthDayCounts[9] = 31;
        monthDayCounts[10] = 30;
        monthDayCounts[11] = 31;

        for (i = 1; i < month; i++) {
            timestamp += monthDayCounts[i - 1] * 1 days;
        }

        // Day
        timestamp += (day - 1) * 1 days;

        return timestamp;
    }

    // Check if year is a leap year
    function isLeapYear(uint256 year) internal pure returns (bool) {
        if (year % 4 != 0) {
            return false;
        } else if (year % 100 != 0) {
            return true;
        } else if (year % 400 != 0) {
            return false;
        } else {
            return true;
        }
    }
}
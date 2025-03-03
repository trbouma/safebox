console.log("Script loaded prescription kooglemidxx");

function roundByQuarter(value) {
    var inv = 1.0 / 0.25;
    return Math.round(value * inv) / inv;
}

function addPlusSign(text) {
    if (text[0] == "-") 
        return text
    else 
        return "+" + text
} 

function validateSph(input) {
    const value = parseFloat(input.value)

    if (isNaN(value)) {
        input.value = ""
        return  
    }

    input.value = addPlusSign(roundByQuarter(value).toFixed(2))
}

function validateCyl(input) {
    const value = parseFloat(input.value)

    if (isNaN(value)) {
        input.value = ""  
        return
    }

    input.value = addPlusSign(roundByQuarter(value).toFixed(2))
}

function validateAxis(input) {
    const value = parseInt(input.value)

    if (isNaN(value)) {
        input.value = ""  
        return
    }

    if (value >= 0 && value <= 180) {
        input.value = value
    } else {
        input.value = ""  
    }
}

function validateAdd(input) {
    const value = parseFloat(input.value)

    if (isNaN(value)) {
        input.value = ""  
        return
    }

    input.value = addPlusSign(roundByQuarter(value).toFixed(2))
}

function validatePD(input) {
    const value = parseFloat(input.value)

    if (isNaN(value)) {
        input.value = ""  
        return
    }

    if (value >= 0 && value <= 50) {
        input.value = value
    } else {
        input.value = ""  
    }
}

function validatePrismValue(input) {
    const value = parseFloat(input.value)

    if (isNaN(value)) {
        input.value = ""  
        return
    }

    if (value >= 0 && value <= 50) {
        input.value = value
    } else {
        input.value = ""  
    }
}


function validatePrismBase(input) {
    const value = parseFloat(input.value)

    if (isNaN(value)) {
        input.value = ""  
        return
    }

    if (value >= 0 && value <= 50) {
        input.value = value
    } else {
        input.value = ""  
    }
}
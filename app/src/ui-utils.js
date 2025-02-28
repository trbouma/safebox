function toggleEdit(ev, currentValueFn, setNewValueFn, editObject) {
    let id = ev.target.id
    let current = currentValueFn();
    let editorId = id + 'editor';
    let editorComponent = "#" + editorId;
    let currentCode = $("#"+id).html()
    $("#"+id).html('');
    editObject
        .attr({
            'id': editorId,
        })
        .on("focusout", function () {
            let newValue = $(editorComponent).val()
            console.log(current, newValue)
            if (current != newValue)
                setNewValueFn(newValue)
            else {
                // cancels
                $(editorComponent).remove()
                $("#"+id).html(currentCode);
            }
        })
        .on("click", function (ev1) {
            ev1.stopPropagation();
        })
        .on("keyup", function (ev2) {
            if (ev2.which == 13) this.blur();
            if (ev2.which == 27) {
                $(editorComponent).val(current)
                this.blur();
            }
        })
        .appendTo("#"+id);
    
    $(editorComponent).val(current)
    $(editorComponent).focus();

    ev.stopPropagation();
}

// UI
function updateListSection(listName, list) {
    if (!listName || !list) return 
    let id = listName.replace("#", "")
    let section = $(listName)
    section.html("")
    list.forEach((item, index) => {
        $('<li></li>').attr({ 'id': id+index }).text(item).appendTo(section)
    })
}



function glassesClick() {
    $("#head-inter-add").show()
    $("#head-add").show()
    $("#head-pd").show()
    $("#head-pd-spacer-container").show()
    $("#head-prism-spacer-container").show()
    $("#head-prism-value").show()
    $("#head-prism-base").show()
    $("#head-curve").hide()
    $("#head-diameter").hide()
    $("#head-brand").hide()

    $("#right-inter-add-container").show()
    $("#right-add-container").show()
    $("#right-pd-container").show()
    $("#right-pd-spacer-container").show()
    $("#right-prism-spacer-container").show()
    $("#right-prism-value-container").show()
    $("#right-prism-base-container").show()
    $("#right-curve-container").hide()
    $("#right-diameter-container").hide()
    $("#right-brand-container").hide()

    $("#left-inter-add-container").show()
    $("#left-add-container").show()
    $("#left-pd-container").show()
    $("#left-pd-spacer-container").show()
    $("#left-prism-spacer-container").show()
    $("#left-prism-value-container").show()
    $("#left-prism-base-container").show()
    $("#left-curve-container").hide()
    $("#left-diameter-container").hide()
    $("#left-brand-container").hide()
}

function contactsClick() {
    $("#head-inter-add").hide()
    $("#head-add").hide()
    $("#head-pd").hide()
    $("#head-pd-spacer-container").hide()
    $("#head-prism-spacer-container").hide()
    $("#head-prism-value").hide()
    $("#head-prism-base").hide()
    $("#head-curve").show()
    $("#head-diameter").show()
    $("#head-brand").show()

    $("#right-inter-add-container").hide()
    $("#right-add-container").hide()
    $("#right-pd-container").hide()
    $("#right-pd-spacer-container").hide()
    $("#right-prism-spacer-container").hide()
    $("#right-prism-value-container").hide()
    $("#right-prism-base-container").hide()
    $("#right-curve-container").show()
    $("#right-diameter-container").show()
    $("#right-brand-container").show()

    $("#left-inter-add-container").hide()
    $("#left-add-container").hide()
    $("#left-pd-container").hide()
    $("#left-pd-spacer-container").hide()
    $("#left-prism-spacer-container").hide()
    $("#left-prism-value-container").hide()
    $("#left-prism-base-container").hide()
    $("#left-curve-container").show()
    $("#left-diameter-container").show()
    $("#left-brand-container").show()
}
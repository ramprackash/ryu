var url = "http://" + location.hostname + ":8080";

function updateIDSRules() {
    var lpRulesBody = document.getElementById('paper-container-ids-rules-lp');
    var dpRulesBody = document.getElementById('paper-container-ids-rules-dp');
    var text = "";
    $.get(url.concat("/ids/lprules"), function(resp){
        var lines = resp.split("\n");
        for (line in lines){
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
            lpRulesBody.appendChild(new_p);
            lpRulesBody.appendChild(document.createElement('BR'));
        }
    });
    $.get(url.concat("/ids/dprules"), function(resp){
//          idsLogsBody.innerHTML = resp;
        var lines = resp.split("\n");
        for (line in lines){
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
            dpRulesBody.appendChild(new_p);
            dpRulesBody.appendChild(document.createElement('BR'));
        }
    });

    
}

updateIDSRules();

//var idsRulesIntervalID = setInterval(function(){updateIDSRules()}, 5000);

//function stopIDSRulesRefresh() {
//    clearInterval(idsRulesIntervalID);
//}

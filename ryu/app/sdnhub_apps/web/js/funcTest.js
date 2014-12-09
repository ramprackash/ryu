var url = "http://" + location.hostname + ":8080";

function functionTest() {
    var alertBody = document.getElementById('paper-container-alert');
    var flowBody = document.getElementById('paper-container-flow');
    var text = "";
    $.get(url.concat("/ids/alert"), function(resp){
        var lines = resp.split("\n");
        for (line in lines){
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
            alertBody.appendChild(new_p);
            alertBody.appendChild(document.createElement('BR'));
        }
    });
    $.get(url.concat("/ids/flow"), function(resp){
//          idsLogsBody.innerHTML = resp;
        var lines = resp.split("\n");
        for (line in lines){
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
            flowBody.appendChild(new_p);
            flowBody.appendChild(document.createElement('BR'));
        }
    });

    
}

functionTest();

//var idsRulesIntervalID = setInterval(function(){updateIDSRules()}, 5000);

//function stopIDSRulesRefresh() {
//    clearInterval(idsRulesIntervalID);
//}

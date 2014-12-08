var url = "http://" + location.hostname + ":8080";

function updateAlerts() {
    var alertsBody = document.getElementById('paper-container-ids-alerts');
    while (alertsBody.firstChild) {
            alertsBody.removeChild(alertsBody.firstChild);
    }
    var text = "";
    $.get(url.concat("/ids/idsalerts"), function(resp){
          alertsBody.innerHTML = resp;
//        var lines = resp.split("\n");
//        for (line in lines){
//            var new_p = document.createElement('FONT');
//            new_p.appendChild(document.createTextNode(lines[line]));
//            portScanBody.appendChild(new_p);
//            portScanBody.appendChild(document.createElement('BR'));
//        }
    });
    
}

updateAlerts();

var alertsIntervalID = setInterval(function(){updateAlerts()}, 5000);

function stopAlertsRefresh() {
    clearInterval(alertsIntervalID);
}

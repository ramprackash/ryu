var url = "http://" + location.hostname + ":8080";

function updateIDSLogs() {
    var idsLogsBody = document.getElementById('ids-logs-data');
    while (idsLogsBody.firstChild) {
            idsLogsBody.removeChild(idsLogsBody.firstChild);
    }
    var text = "";
    $.get(url.concat("/ids/logs"), function(resp){
          idsLogsBody.innerHTML = resp;
//        var lines = resp.split("\n");
//        for (line in lines){
//            var new_p = document.createElement('FONT');
            //new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
//            idsLogsBody.appendChild(new_p);
//            idsLogsBody.appendChild(document.createElement('BR'));
//        }
    });
    
}

updateIDSLogs();

var idsLogsIntervalID = setInterval(function(){updateIDSLogs()}, 5000);

function stopIDSLogsRefresh() {
    clearInterval(idsLogsIntervalID);
}

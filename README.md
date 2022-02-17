# VolterraSentinelConnector


## Information you should have on your Volterra account
Get your API Authorization Token from your Volterra account.
You should also have your **tenant** and your **namespace**

## Pre-tasks
### Create a Resource Group



### Create a Log Analytics workspace
get the workspace ID and a Workspace Key for your Log Analytics Workspace.




### Run this template:

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Ffchmainy%2FVolterraSentinelConnector%2Fmain%2Fazuredeploy.json)  [![Visualize](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.svg?sanitize=true)](http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Ffchmainy%2FVolterraSentinelConnector%2Fmain%2Fazuredeploy.json)


### Use AZ CLI

```Powershell
az account set -s {subscriptionID}
az group create --name {resourceGroupName} --location westEurope
az deployment group create -g {resourceGroupName} --template-uri https://raw.githubusercontent.com/fchmainy/VolterraSentinelConnector/main/azuredeploy.json --parameters @parameters.json
```

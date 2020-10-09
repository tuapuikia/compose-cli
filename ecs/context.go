/*
   Copyright 2020 Docker Compose CLI authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package ecs

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"gopkg.in/ini.v1"

	"github.com/docker/compose-cli/context/store"
	"github.com/docker/compose-cli/errdefs"
	"github.com/docker/compose-cli/prompt"
)

type contextCreateAWSHelper struct {
	user prompt.UI
}

func newContextCreateHelper() contextCreateAWSHelper {
	return contextCreateAWSHelper{
		user: prompt.User{},
	}
}

func (h contextCreateAWSHelper) createProfile(name string) error {
	accessKey, secretKey, err := h.askCredentials()
	if err != nil {
		return err
	}
	if accessKey != "" && secretKey != "" {
		return h.saveCredentials(name, accessKey, secretKey)
	}
	return nil
}

func (h contextCreateAWSHelper) createContextData(_ context.Context, opts ContextParams) (interface{}, string, error) {
	ecsCtx := store.EcsContext{
		Profile: opts.Profile,
		Region:  opts.Region,
	}
	profilesList, err := h.getProfiles()
	if err != nil {
		return nil, "", err
	}
	if ecsCtx.Profile != "" {
		// validate profile
		if !contains(profilesList, ecsCtx.Profile) {
			return nil, "", fmt.Errorf("profile not found")
		}
	}

	if h.haveRequiredFlags(ecsCtx) {
		if ecsCtx.Profile == "default" {
			ecsCtx.Profile = ""
		}
		description := strings.TrimSpace(
			fmt.Sprintf("%s (%s)", opts.Description, ecsCtx.Region))
		return ecsCtx, description, nil
	}

	profile, err := h.chooseProfile(profilesList)
	if err != nil {
		return nil, "", err
	}

	// set region
	region, err := h.chooseRegion(ecsCtx.Region, profile)
	if err != nil {
		return nil, "", err
	}
	ecsCtx.Region = region
	ecsCtx.Profile = profile
	if ecsCtx.Profile == "default" {
		ecsCtx.Profile = ""
	}
	description := strings.TrimSpace(
		fmt.Sprintf("%s (%s)", opts.Description, ecsCtx.Region))
	return ecsCtx, description, nil
}

func (h contextCreateAWSHelper) haveRequiredFlags(ctx store.EcsContext) bool {
	if ctx.Profile == "" || ctx.Region == "" {
		return false
	}
	return true
}

func (h contextCreateAWSHelper) saveCredentials(profile string, accessKeyID string, secretAccessKey string) error {
	p := credentials.SharedCredentialsProvider{Profile: profile}
	_, err := p.Retrieve()
	if err == nil {
		return fmt.Errorf("credentials already exist")
	}
	if err.(awserr.Error).Code() == "SharedCredsLoad" && err.(awserr.Error).Message() == "failed to load shared credentials file" {
		_, err := os.Create(p.Filename)
		if err != nil {
			return err
		}
	}
	credIni, err := ini.Load(p.Filename)
	if err != nil {
		return err
	}
	section, err := credIni.NewSection(profile)
	if err != nil {
		return err
	}
	_, err = section.NewKey("aws_access_key_id", accessKeyID)
	if err != nil {
		return err
	}
	_, err = section.NewKey("aws_secret_access_key", secretAccessKey)
	if err != nil {
		return err
	}
	return credIni.SaveTo(p.Filename)
}

func (h contextCreateAWSHelper) getProfiles() ([]string, error) {
	profiles := []string{}
	// parse both .aws/credentials and .aws/config for profiles
	configFiles := map[string]bool{
		defaults.SharedCredentialsFilename(): false,
		defaults.SharedConfigFilename():      true,
	}
	for f, prefix := range configFiles {
		config, err := loadIniFile(f, prefix)
		if err != nil {
			if strings.Contains(err.Error(), "no such file or directory") {
				continue
			}
			return nil, err
		}
		for name := range config {
			profiles = append(profiles, name)
		}
	}
	return profiles, nil
}

func (h contextCreateAWSHelper) chooseProfile(profiles []string) (string, error) {
	options := []string{"new profile"}
	options = append(options, profiles...)

	selected, err := h.user.Select("Select AWS Profile", options)
	if err != nil {
		if err == terminal.InterruptErr {
			return "", errdefs.ErrCanceled
		}
		return "", err
	}
	profile := options[selected]
	if options[selected] == "new profile" {
		suggestion := ""
		if !contains(profiles, "default") {
			suggestion = "default"
		}
		name, err := h.user.Input("profile name", suggestion)
		if err != nil {
			return "", err
		}
		return name, h.createProfile(name)
	}
	return profile, nil
}

func (h contextCreateAWSHelper) chooseRegion(region string, profile string) (string, error) {
	suggestion := region

	// only load ~/.aws/config
	awsConfig := defaults.SharedConfigFilename()
	configIni, err := ini.Load(awsConfig)

	if err != nil {
		if !strings.Contains(err.Error(), "no such file or directory") {
			return "", err
		}
		configIni = ini.Empty()
	}
	if profile != "default" {
		profile = fmt.Sprintf("profile %s", profile)
	}
	section, err := configIni.GetSection(profile)
	if err != nil {
		if !strings.Contains(err.Error(), "does not exist") {
			return "", err
		}
		section, err = configIni.NewSection(profile)
		if err != nil {
			return "", err
		}
	}
	reg, err := section.GetKey("region")
	if err == nil {
		suggestion = reg.Value()
	}
	// promp user for region
	region, err = h.user.Input("Region", suggestion)
	if err != nil {
		return "", err
	}
	// save selected/typed region under profile in ~/.aws/config
	_, err = section.NewKey("region", region)
	if err != nil {
		return "", err
	}
	return region, configIni.SaveTo(awsConfig)
}

func (h contextCreateAWSHelper) askCredentials() (string, string, error) {
	confirm, err := h.user.Confirm("Enter AWS credentials", false)
	if err != nil {
		return "", "", err
	}
	if !confirm {
		return "", "", nil
	}

	accessKeyID, err := h.user.Input("AWS Access Key ID", "")
	if err != nil {
		return "", "", err
	}
	secretAccessKey, err := h.user.Password("Enter AWS Secret Access Key")
	if err != nil {
		return "", "", err
	}
	// validate access ID and password
	if len(accessKeyID) < 3 || len(secretAccessKey) < 3 {
		return "", "", fmt.Errorf("AWS Access/Secret Access Key must have more than 3 characters")
	}
	return accessKeyID, secretAccessKey, nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func keys(section map[string]ini.Section) []string {
	keys := reflect.ValueOf(section).MapKeys()
	profiles := make([]string, len(keys))
	for i := 0; i < len(keys); i++ {
		profiles[i] = keys[i].String()
	}
	return profiles
}

func loadIniFile(path string, prefix bool) (map[string]ini.Section, error) {
	profiles := map[string]ini.Section{}
	credIni, err := ini.Load(path)
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			return nil, nil
		}
		return nil, err
	}
	for _, section := range credIni.Sections() {
		if prefix && strings.HasPrefix(section.Name(), "profile ") {
			profiles[section.Name()[len("profile "):]] = *section
		} else if !prefix || section.Name() == "default" {
			profiles[section.Name()] = *section
		}
	}
	return profiles, nil
}

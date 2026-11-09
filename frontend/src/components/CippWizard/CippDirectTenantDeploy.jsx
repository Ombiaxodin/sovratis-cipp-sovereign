import { useEffect } from "react";
import { Stack, Box, Typography, Link } from "@mui/material";
// [SOVRATIS OVERRIDE START]
import { TextField, MenuItem } from "@mui/material";
// [SOVRATIS OVERRIDE END]
import { CIPPM365OAuthButton } from "../CippComponents/CIPPM365OAuthButton";
import { CippApiResults } from "../CippComponents/CippApiResults";
// [SOVRATIS OVERRIDE START]
// upstream: import { ApiPostCall } from "../../api/ApiCall";
import { ApiGetCall, ApiPostCall } from "../../api/ApiCall";
// [SOVRATIS OVERRIDE END]
import { CippWizardStepButtons } from "./CippWizardStepButtons";

export const CippDirectTenantDeploy = (props) => {
  const { formControl, currentStep, onPreviousStep, onNextStep } = props;

  formControl.register("DirectTenantAuth", {
    required: true,
  });

  const addTenant = ApiPostCall({ urlfromdata: true, relatedQueryKeys: ["tenants-table"] });

  // [SOVRATIS OVERRIDE START]
  // Cloud environment of the tenant being added. Required, defaults to Global. It is immutable after
  // onboarding (a tenant that moves clouds must be removed and added again), so it is chosen up front.
  formControl.register("cloudEnvironment", { required: true });
  const cloudEnvironment = formControl.watch("cloudEnvironment") ?? "Global";
  const appIdInfo = ApiGetCall({ url: "/api/ExecListAppId", queryKey: "listAppId", waiting: true });
  const cloudOptions = appIdInfo?.data?.cloudEnvironments ?? [{ name: "Global", configured: true }];

  useEffect(() => {
    if (!formControl.getValues("cloudEnvironment")) {
      formControl.setValue("cloudEnvironment", "Global", { shouldValidate: true });
    }
  }, [formControl]);
  // [SOVRATIS OVERRIDE END]

  useEffect(() => {
    if (addTenant.isSuccess) {
      formControl.setValue("DirectTenantAuth", true);
      formControl.trigger("DirectTenantAuth");
    }
  }, [addTenant.isSuccess, formControl]);

  return (
    <Stack spacing={2}>
      <Box>
        <Typography variant="h6" gutterBottom>
          Per-Tenant Authentication
        </Typography>
        <Typography variant="body2" sx={{ mt: 2, mb: 2 }}>
          Click the button below to connect to individual tenants. This option allows you to
          authenticate directly to a tenant without using GDAP or Partner Center relationships.
        </Typography>
        <Typography variant="body2" sx={{ mt: 2, mb: 2 }}>
          You can authenticate to multiple tenants by repeating this step for each tenant you want
          to add. More information about per-tenant authentication can be found in the{" "}
          <Link
            href="https://docs.cipp.app/setup/installation/gdap-invite-wizard#wizard-steps-for-direct-tenants"
            target="_blank"
            rel="noopener noreferrer"
          >
            authentication documentation
          </Link>
          .
        </Typography>

        {/* [SOVRATIS OVERRIDE START] */}
        <Box sx={{ mt: 2, mb: 2, maxWidth: 420 }}>
          <TextField
            select
            required
            fullWidth
            size="small"
            label="Cloud Environment"
            value={cloudEnvironment}
            onChange={(event) =>
              formControl.setValue("cloudEnvironment", event.target.value, { shouldValidate: true })
            }
            disabled={addTenant.isPending}
            helperText="The cloud the tenant lives in. This cannot be changed after onboarding; to move a tenant, remove it and add it again."
          >
            {cloudOptions.map((cloud) => (
              <MenuItem key={cloud.name} value={cloud.name} disabled={!cloud.configured}>
                {cloud.configured ? cloud.name : `${cloud.name} (not configured)`}
              </MenuItem>
            ))}
          </TextField>
        </Box>
        {/* [SOVRATIS OVERRIDE END] */}

        <Box sx={{ display: "flex", justifyContent: "flex-start", mt: 2, mb: 2 }}>
          <Stack direction="row" spacing={2} sx={{
            alignItems: "center"
          }}>
            <CIPPM365OAuthButton
              // [SOVRATIS OVERRIDE START]
              key={cloudEnvironment}
              cloudEnvironment={cloudEnvironment}
              // [SOVRATIS OVERRIDE END]
              onAuthSuccess={(tokenData) => {
                const updatedTokenData = {
                  ...tokenData,
                  tenantMode: "perTenant",
                  // [SOVRATIS OVERRIDE START]
                  cloudEnvironment,
                  // [SOVRATIS OVERRIDE END]
                };
                addTenant.mutate({
                  url: "/api/ExecAddTenant",
                  data: updatedTokenData,
                });
              }}
              buttonText="Connect to Tenant"
              showSuccessAlert={false}
              scope="https://graph.microsoft.com/DelegatedPermissionGrant.ReadWrite.All https://graph.microsoft.com/Directory.ReadWrite.All https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All offline_access profile openid"
            />
          </Stack>
        </Box>

        <CippApiResults apiObject={addTenant} />
      </Box>

      <CippWizardStepButtons
        currentStep={currentStep}
        onPreviousStep={onPreviousStep}
        onNextStep={onNextStep}
        formControl={formControl}
        noSubmitButton={true}
      />
    </Stack>
  );
};

export default CippDirectTenantDeploy;

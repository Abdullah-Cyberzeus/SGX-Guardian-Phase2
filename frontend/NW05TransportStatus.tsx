import { useNavigate } from "react-router";
import { OB01Welcome } from "../screens/onboarding/OB01Welcome";

export function WelcomePage() {
  const navigate = useNavigate();

  return (
    <OB01Welcome
      onGetStarted={() => {
        // Will navigate to OB-02 when built
        console.log("Get Started tapped");
      }}
      onLearnMore={() => {
        // Will open a Learn More sheet when built
        console.log("Learn More tapped");
      }}
    />
  );
}

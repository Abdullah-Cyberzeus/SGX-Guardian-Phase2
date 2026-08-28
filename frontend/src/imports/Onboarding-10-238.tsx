import svgPaths from "./svg-56hiz8oofe";

function TextButton() {
  return (
    <div className="-translate-x-1/2 absolute contents left-[calc(50%+89px)] top-[757px]" data-name="Text Button">
      <p className="-translate-x-1/2 absolute font-['Space_Grotesk:Medium',sans-serif] font-medium leading-[1.2] left-[calc(50%+89px)] text-[#0ba375] text-[14px] text-center top-[757px] tracking-[-0.3px] whitespace-nowrap">Login</p>
    </div>
  );
}

function Cta() {
  return (
    <div className="absolute contents left-[30px] top-[683px]" data-name="CTA">
      <div className="absolute bg-[#0ba375] h-[54px] left-[30px] rounded-[12px] top-[683px] w-[315px]" data-name="Background" />
      <p className="absolute font-['Space_Grotesk:SemiBold',sans-serif] leading-[22px] left-[calc(50%-29.5px)] not-italic text-[16px] text-white top-[699px] whitespace-nowrap">Sign Up</p>
    </div>
  );
}

function Footer() {
  return (
    <div className="absolute contents left-[30px] top-[683px]" data-name="Footer">
      <TextButton />
      <p className="-translate-x-1/2 absolute font-['Space_Grotesk:Regular',sans-serif] font-normal leading-[1.2] left-[calc(50%-22px)] text-[#9b9b9b] text-[14px] text-center top-[757px] tracking-[-0.3px] whitespace-nowrap">Already have an account?</p>
      <Cta />
    </div>
  );
}

function Slider() {
  return (
    <div className="absolute contents left-[158px] top-[643px]" data-name="Slider">
      <div className="absolute bg-[#454545] h-[6px] left-[209px] rounded-[5px] top-[643px] w-[9px]" />
      <div className="absolute bg-[#454545] h-[6px] left-[194px] rounded-[5px] top-[643px] w-[9px]" />
      <div className="absolute bg-[#454545] h-[6px] left-[179px] rounded-[5px] top-[643px] w-[9px]" />
      <div className="absolute bg-[#0ba375] h-[6px] left-[158px] rounded-[5px] top-[643px] w-[15px]" />
    </div>
  );
}

function HeadlineBodycopy() {
  return (
    <div className="-translate-x-1/2 absolute contents leading-[normal] left-[calc(50%+0.5px)] text-center top-[453px] tracking-[-0.3px]" data-name="Headline & Bodycopy">
      <p className="-translate-x-1/2 absolute font-['Space_Grotesk:Regular',sans-serif] font-normal left-[calc(50%+0.5px)] text-[#9b9b9d] text-[14px] top-[543px] w-[280px]">{`Welcome to DataSentinel Mobile – the ultimate solution for securing your data, wherever you go. Let's protect your digital world together.`}</p>
      <p className="-translate-x-1/2 absolute font-['Space_Grotesk:SemiBold',sans-serif] left-[calc(50%+0.5px)] not-italic text-[#efefef] text-[30px] top-[453px] w-[288px]">Your Digital Safety Starts Here</p>
    </div>
  );
}

function Header() {
  return (
    <div className="-translate-x-1/2 absolute h-[11.264px] left-[calc(50%+0.64px)] top-[18px] w-[273.711px]" data-name="Header">
      <svg className="absolute block size-full" fill="none" preserveAspectRatio="none" viewBox="0 0 273.711 11.2637">
        <g id="Header">
          <g id="Right">
            <path d={svgPaths.p2141deb0} fill="var(--fill-0, white)" id="Cellular Connection" />
            <path d={svgPaths.p3bb0d180} fill="var(--fill-0, white)" id="Wifi" />
          </g>
          <g id="Time">
            <path d={svgPaths.p35f59100} fill="var(--fill-0, white)" />
            <path d={svgPaths.pd29c00} fill="var(--fill-0, white)" />
            <path d={svgPaths.p126c7900} fill="var(--fill-0, white)" />
            <path d={svgPaths.pe6fdd00} fill="var(--fill-0, white)" />
          </g>
        </g>
      </svg>
    </div>
  );
}

export default function Onboarding() {
  return (
    <div className="bg-[#090a10] relative size-full" data-name="Onboarding">
      <Footer />
      <Slider />
      <HeadlineBodycopy />
      <div className="absolute bg-[#c4c4c4] h-[421px] left-0 top-0 w-[375px]" data-name="Image" />
      <Header />
    </div>
  );
}

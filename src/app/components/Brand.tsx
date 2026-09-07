import logo from "../../assets/afranet-logo.webp";

/**
 * The Afranet mark. The artwork is navy (#164194) on transparency, which scores
 * about 1.8:1 against the dark theme's surface — far below the 3:1 a graphic
 * needs to stay legible — so in dark mode it sits on a white plate rather than
 * being recoloured, which would misrepresent the brand. The padding is present
 * in both themes so the geometry does not shift between them.
 */
export default function Brand({ className = "h-6" }: { className?: string }) {
  return (
    <img
      src={logo}
      alt="افرانت"
      width={198}
      height={51}
      className={`${className} w-auto p-1 rounded-sm dark:bg-white`}
    />
  );
}

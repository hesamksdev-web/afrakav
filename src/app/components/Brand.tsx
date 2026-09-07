import logoLight from "../../assets/afranet-logo.webp";
import logoDark from "../../assets/afranet-logo-dark.webp";

/**
 * The Afranet mark.
 *
 * The delivered artwork is navy on transparency, which measures about 1.8:1
 * against the dark theme's surface — well under the 3:1 a graphic needs to stay
 * legible. Rather than sitting it on a white plate, which reads as a sticker on
 * a dark interface, the wordmark is redrawn in white for dark backgrounds with
 * the brand red kept (see scripts/make-dark-logo.py). Both files ship and CSS
 * picks one, so there is no flash of the wrong mark on load.
 */
export default function Brand({ className = "h-7" }: { className?: string }) {
  const shared = `${className} w-auto select-none`;
  return (
    <span className="inline-flex flex-shrink-0" aria-label="افرانت" role="img">
      <img src={logoLight} alt="" width={198} height={51} className={`${shared} dark:hidden`} />
      <img src={logoDark} alt="" width={198} height={51} className={`${shared} hidden dark:block`} />
    </span>
  );
}

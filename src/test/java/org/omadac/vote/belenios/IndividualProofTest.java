package org.omadac.vote.belenios;

import static org.assertj.core.api.Assertions.assertThat;
import static org.omadac.vote.belenios.ModularChecksum.checksum;

import java.math.BigInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.model.Group;

import ch.openchvote.algorithms.general.GenRandomInteger;

public class IndividualProofTest {

    private static final Group GROUP = Groups.HOMOMORPHIC;
    private static final BigInteger p = GROUP.p();
    private static final BigInteger q = GROUP.q();
    private static final BigInteger g = GROUP.g();

    private static final BigInteger publicCred = new BigInteger(
        "10029862746834958143319323111454409387590534954793044404822945369994744260442089371115262190203934804675786564182282779251355216210946054924334240642428855729296421330257013472191135818728983762408033399214480787226293273548568201935296926228677329878383724409798063156434251931695634528137005735620183893704077873291267277770009834510370291772787286847855329543445255587222293360124381540329014428549828158233880255987012301417548047705955061799010400287887972369638914661074191768045129220621711681227211225478992052827599600084274797905069932956260221255187797967125498373990647751773001873864960847565145552988003");

    private static final BigInteger y = new BigInteger(
        "18478552998180328667106906340577036974200817227539334863676532422469343800372421137983128363433767107955978948874170135740975765034281891297373426576746131056846916490488514778086067290097061454354438724172048537407092198537584541460810028468333282993909514621570021059418748679867109859300387097647274988671544915825757967768321757101125125020532042302595133017298396529736850149438621537801933494966736664488998687266352904437624506311550413618334147435818520750495585767657390129003607859684653220753010403901703707231751721585479176565736548881849869631858790203164163794609503125964506657044947994195413651141720");

    private static final BigInteger alpha0 = new BigInteger(
        "12004216984434922431785955274114640240186456316190944993212160497845519644877164985049440474627462469668888942816425412947226744605285424335433301784275540475508192832311891953055823679256069864186277539661624617793756288645041173595889413063316760270827378388756477634341087063181961301312334137325883972737742872840570974493653265766351428927272240056192847145604195758527521355709488277057414629018323026919181115523944482948064774271751425408645314904231535098356338569720050077006757249334630573643394322247551294389141133789137481644601934799393714696365781368986481302755996222135396905099745723504563348498769");
    private static final BigInteger beta0 = new BigInteger(
        "13301504955226444830416825101073109985325567014519970229584782534377060365257094269179811107580667158540181410973525336223344689306447147674865259919673399364885953503999987925850657561524948731758435612158917019291217489157574872815332307810606909275670946708830231807983401306975000570530044241564021799293876208391949105766069821973697457406944786002791747606057570581785014327853261907566208969255678001793262459579426826370062034205476962770635663220268054244056516164657967665180189736648009147567336207361426681499893946373931757067439935339781873766495429340612914345067386159026770608317030432712337553962788");
    private static final BigInteger alpha1 = new BigInteger(
        "16584829270044635577071890807716541075287786623797867571790372062806192259730096863287429831943846010420009705127278212804576610959463694706450905097424969401182205236031279202648986398735671130120075971751079010133621734268197932642465258233268792763251343377775125455957329676981378378496641472399721652544328774199991988726127814323826055224011521244704019597616068208907971156367063387330500805305587261786415477677681779181029146300757833740403050809743989863739920802379227066421159913489192670372008263839710494525803908570622339254792420447147271014301836275296118987168276701233571401678473294900897379245731");
    private static final BigInteger beta1 = new BigInteger(
        "11580558372423088901358748058485806741683054355365905522245232355919194506032632966049306395119471967737785055221216116947235580874600114263287037048042579940207169553578318300993067857394439213513716142685503669185544842719884097112011934495197925508552966461444309315695656992600005181530052776666829312780643697958697363251969429586504040887695136088914756432798485076414933798508939020556596346753884388750255030463223904143138141567162570440555540414781058441295301554849551824791059302559398407234448857973140358701923332062201529639587720822820369822078673798904005150197325915398919804017372852045112386280466");
    private static final BigInteger alpha2 = new BigInteger(
        "20608083788694448781829676044722338106478239987732805322425006792508516491947985577187724323128313798400473748836612443692895296080509494202241542732616734206751741915716704862431409022986421439367447004852146876653567123819110954374272871100105236060381369267629837597556034792462036125301695913259522058786716141972391596412969540654309188191939775677381980446642605310583940035397449454117634418607589574187840869561275582096200440152065550798486924706558929495378227863386156641618850691678381933687769252605925444743126175989570882161422065637721374222419491140950579771788353600663120868918079291691718998165945");
    private static final BigInteger beta2 = new BigInteger(
        "8666632132639617457361624968294506315878956315703864509433423736862253694376228234519153084363346890431067997138265787278391355995476462041836169394375922262952262639310742340789867690305805778316086898155017067985135865410453242326222878473916841891339493776300038431797699248907845132640907364003915356262317214937994769531315757797560124481661069151265961631695083824441687567798557166653669435758690832097326138102804815861963999110068517239382965782189655231746250695465414962981266067180324633799677641915780850612647147900421155557480974409183708740906777406614136459920686975616851527040666395901983023093251");

    private static final BigInteger alphaSigma = alpha1.multiply(alpha2).mod(p);
    private static final BigInteger betaSigma = beta1.multiply(beta2).mod(p);

    private static final String P = Stream.of(g, y, alpha0, beta0, alphaSigma, betaSigma)
        .map(BigInteger::toString)
        .collect(Collectors.joining(","));

    // Vote was 1 (out of 0 or 1)
    @Test
    public void checkPositiveVote() {
        var alpha = new BigInteger(
            "20608083788694448781829676044722338106478239987732805322425006792508516491947985577187724323128313798400473748836612443692895296080509494202241542732616734206751741915716704862431409022986421439367447004852146876653567123819110954374272871100105236060381369267629837597556034792462036125301695913259522058786716141972391596412969540654309188191939775677381980446642605310583940035397449454117634418607589574187840869561275582096200440152065550798486924706558929495378227863386156641618850691678381933687769252605925444743126175989570882161422065637721374222419491140950579771788353600663120868918079291691718998165945");
        var beta = new BigInteger(
            "8666632132639617457361624968294506315878956315703864509433423736862253694376228234519153084363346890431067997138265787278391355995476462041836169394375922262952262639310742340789867690305805778316086898155017067985135865410453242326222878473916841891339493776300038431797699248907845132640907364003915356262317214937994769531315757797560124481661069151265961631695083824441687567798557166653669435758690832097326138102804815861963999110068517239382965782189655231746250695465414962981266067180324633799677641915780850612647147900421155557480974409183708740906777406614136459920686975616851527040666395901983023093251");
        var challenge0 = new BigInteger(
            "40499156981922026794913984473003153626063272526730946017795268514791070731503");
        var response0 = new BigInteger("70679054358573773181332606632913804668629021291236304310329476189474202351399");
        var challenge1 = new BigInteger(
            "76271599986216973645268772466356215847308174816909730092977235328915836686814");
        var response1 = new BigInteger("25349144410434771078433609109388119586341105772404174050375412124598557993203");

        verifyVote(alpha, beta, challenge0, response0, challenge1, response1);
    }

    private void verifyVote(BigInteger alpha, BigInteger beta, BigInteger challenge0, BigInteger response0,
        BigInteger challenge1, BigInteger response1) {
        var a0Num = g.modPow(response0, p);
        var a0Denom = alpha.modPow(challenge0, p);
        var a0 = a0Num.multiply(a0Denom.modInverse(p)).mod(p);

        var b0Num = y.modPow(response0, p);
        var b0Denom = beta.modPow(challenge0, p);
        var b0 = b0Num.multiply(b0Denom.modInverse(p)).mod(p);

        var a1Num = g.modPow(response1, p);
        var a1Denom = alpha.modPow(challenge1, p);
        var a1 = a1Num.multiply(a1Denom.modInverse(p)).mod(p);

        var b1Num = y.modPow(response1, p);
        var b1Denom = beta.multiply(g.modInverse(p)).modPow(challenge1, p);
        var b1 = b1Num.multiply(b1Denom.modInverse(p)).mod(p);

        var challenges = challenge0.add(challenge1).mod(q);

        //prove|S|α,β|A0,B0,...,Ak,Bk

        String message = String.format("prove|%s|%s,%s|%s,%s,%s,%s", publicCred,
            alpha, beta,
            a0, b0, a1, b1);

        var checksum = checksum(message, q);

        assertThat(challenges).isEqualTo(checksum);
    }

    // Vote was 0 (out of 0 or 1)
    @Test
    public void checkNegativeVote() {
        var alpha = new BigInteger(
            "16584829270044635577071890807716541075287786623797867571790372062806192259730096863287429831943846010420009705127278212804576610959463694706450905097424969401182205236031279202648986398735671130120075971751079010133621734268197932642465258233268792763251343377775125455957329676981378378496641472399721652544328774199991988726127814323826055224011521244704019597616068208907971156367063387330500805305587261786415477677681779181029146300757833740403050809743989863739920802379227066421159913489192670372008263839710494525803908570622339254792420447147271014301836275296118987168276701233571401678473294900897379245731");
        var beta = new BigInteger(
            "11580558372423088901358748058485806741683054355365905522245232355919194506032632966049306395119471967737785055221216116947235580874600114263287037048042579940207169553578318300993067857394439213513716142685503669185544842719884097112011934495197925508552966461444309315695656992600005181530052776666829312780643697958697363251969429586504040887695136088914756432798485076414933798508939020556596346753884388750255030463223904143138141567162570440555540414781058441295301554849551824791059302559398407234448857973140358701923332062201529639587720822820369822078673798904005150197325915398919804017372852045112386280466");
        var challenge0 = new BigInteger(
            "36698047268027774419577391405142175270459077598710365664863757598848877312570");
        var response0 = new BigInteger("61799118486361278849326602303837341562611263033576870585904866250982948995590");
        var challenge1 = new BigInteger(
            "55860395668443925066161164853646746995729228925189652870200762917602477094633");
        var response1 = new BigInteger("31952975885180121387954955389831068268650598335965116803032550293486802568578");

        verifyVote(alpha, beta, challenge0, response0, challenge1, response1);
    }

    @Test
    public void createPositiveProof() {
        var r = GenRandomInteger.run(q);
        var alpha = g.modPow(r, p);
        var beta = y.modPow(r, p).multiply(g).mod(p);

        var challenge0 = GenRandomInteger.run(q);
        var response0 = GenRandomInteger.run(q);

        var a0Num = g.modPow(response0, p);
        var a0Denom = alpha.modPow(challenge0, p);
        var a0 = a0Num.multiply(a0Denom.modInverse(p)).mod(p);

        var b0Num = y.modPow(response0, p);
        var b0Denom = beta.modPow(challenge0, p);
        var b0 = b0Num.multiply(b0Denom.modInverse(p)).mod(p);

        var w = GenRandomInteger.run(q);
        var a1 = g.modPow(w, p);
        var b1 = y.modPow(w, p);

        var message = String.format("prove|%s|%s,%s|%s,%s,%s,%s", publicCred.toString(),
            alpha.toString(), beta.toString(),
            a0.toString(), b0.toString(), a1.toString(), b1.toString());

        var checksum = checksum(message, q);

        var challenge1 = checksum.subtract(challenge0).mod(q);
        var response1 = challenge1.multiply(r).add(w).mod(q);

        verifyVote(alpha, beta, challenge0, response0, challenge1, response1);
    }

    @Test
    public void createNegativeProof() {
        var r = GenRandomInteger.run(q);
        var alpha = g.modPow(r, p);
        var beta = y.modPow(r, p).mod(p);

        var w = GenRandomInteger.run(q);
        var a0 = g.modPow(w, p);
        var b0 = y.modPow(w, p);

        var challenge1 = GenRandomInteger.run(q);
        var response1 = GenRandomInteger.run(q);

        var a1Num = g.modPow(response1, p);
        var a1Denom = alpha.modPow(challenge1, p);
        var a1 = a1Num.multiply(a1Denom.modInverse(p)).mod(p);

        var b1Num = y.modPow(response1, p);
        var b1Denom = beta.multiply(g.modInverse(p)).modPow(challenge1, p);
        var b1 = b1Num.multiply(b1Denom.modInverse(p)).mod(p);

        var message = String.format("prove|%s|%s,%s|%s,%s,%s,%s", publicCred.toString(),
            alpha.toString(), beta.toString(),
            a0.toString(), b0.toString(), a1.toString(), b1.toString());

        var checksum = checksum(message, q);

        var challenge0 = checksum.subtract(challenge1).mod(q);
        var response0 = challenge0.multiply(r).add(w).mod(q);

        verifyVote(alpha, beta, challenge0, response0, challenge1, response1);
    }

    @Test
    public void checkBlankProofNegative() {
        var challenge0 = new BigInteger(
            "25704976438123310010011481969398800651195521744066114921687758825025645684164");
        var response0 = new BigInteger("12075388095789634762670717965361170792754350183231453537994174402515319117651");
        var challengeSigma = new BigInteger(
            "2889477741401203379705175917472803654749422619048367993667549679614487694489");
        var responseSigma = new BigInteger(
            "14446606861696551952676599487196072090194037658673065687932472311409560814154");

        var a0 = g.modPow(response0, p).multiply(alpha0.modPow(challenge0, p)).mod(p);
        var b0 = y.modPow(response0, p).multiply(beta0.modPow(challenge0, p)).mod(p);
        var aSigma = g.modPow(responseSigma, p)
            .multiply(alphaSigma.modPow(challengeSigma, p))
            .mod(p);
        var bSigma = y.modPow(responseSigma, p)
            .multiply(betaSigma.modPow(challengeSigma, p))
            .mod(p);

        String message = String.format("bproof0|%s|%s|%s,%s,%s,%s", publicCred, P, a0, b0, aSigma, bSigma);
        var checksum = checksum(message, q);

        var challenges = challenge0.add(challengeSigma).mod(q);
        assertThat(challenges).isEqualTo(checksum);
    }

    @Test
    public void checkOverallProofNonBlank() {
        var challenge0 = new BigInteger(
            "64666551742949618624372865756326388359925035868128627802661080078403008563433");
        var response0 = new BigInteger("24792183340286970919985216202487223543748438871016957751972514659168210162141");
        var challenge1 = new BigInteger(
            "48923039012904529278357586419185419274872360102661259814597162020164598416452");
        var response1 = new BigInteger("72606144240974168926016259219947919368939342658614024389385741081545367315138");

        var a0 = g.modPow(response0, p).multiply(alpha0.modPow(challenge0, p)).mod(p);
        var b0 = y.modPow(response0, p)
            .multiply(beta0.multiply(g.modInverse(p)).modPow(challenge0, p)).mod(p);

        var a1 = g.modPow(response1, p).multiply(alphaSigma.modPow(challenge1, p)).mod(p);
        var b1 = y.modPow(response1, p)
            .multiply(betaSigma.multiply(g.modInverse(p)).modPow(challenge1, p)).mod(p);

        String message = String.format("bproof1|%s|%s|%s,%s,%s,%s", publicCred, P, a0, b0, a1, b1);
        var checksum = checksum(message, q);

        var challenges = challenge0.add(challenge1).mod(q);
        assertThat(challenges).isEqualTo(checksum);
    }

    @Test
    public void verifySignature() {
        var challenge = new BigInteger("10540365264599746922012592620571036783723825915710258257893603712079141532301");
        var response = new BigInteger("29449519802209292290638380652163484108771059520521054401194001601662341969970");

        var a = g.modPow(response, p).multiply(publicCred.modPow(challenge, p)).mod(p);
        String message = String.format("sig|%s|%s|%s,%s,%s,%s,%s,%s", publicCred, a, alpha0, beta0, alpha1, beta1,
            alpha2, beta2);
        var checksum = checksum(message, q);
        assertThat(challenge).isEqualTo(checksum);
    }
}
